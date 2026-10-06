"""Local and hosted Flask dashboard for privacy-preserving flow monitoring."""

from __future__ import annotations

import csv
import html
import json
import logging
import os
import secrets
import time
import zlib
from collections import OrderedDict, defaultdict, deque
from datetime import UTC, datetime
from functools import lru_cache
from io import BytesIO, StringIO
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    Request,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
    stream_with_context,
)
from flask_socketio import SocketIO
from socketio import WSGIApp
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from artifacts import ArtifactError
from pcap_reader import CaptureError
from pipeline import AnalysisError, AnalysisPipeline

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
MODEL_DIR = BASE_DIR / "models"
SAMPLE_DIR = BASE_DIR / "sample_data"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_FLOWS = 25_000
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
RATE_LIMIT_REQUESTS = 8
RATE_LIMIT_WINDOW = 60
RESULT_CACHE_SIZE = 12
RESULT_CACHE_TTL = 15 * 60
RESULT_CACHE_MAX_BYTES = 64 * 1024 * 1024
CORS_ALLOWED_ORIGINS = tuple(
    origin.strip().rstrip("/")
    for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)


class MemoryOnlyRequest(Request):
    """Keep Werkzeug's multipart upload buffers in memory rather than disk."""

    def _get_file_stream(self, total_content_length, filename, content_type, content_length=None):
        return BytesIO()


class JsonLogFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "time": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }, separators=(",", ":"))


def _configure_logging(app):
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    app.logger.handlers[:] = [handler]
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "dashboard" / "templates"),
    static_folder=str(BASE_DIR / "dashboard" / "static"),
)
app.request_class = MemoryOnlyRequest
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 64 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)
_configure_logging(app)

# Flask-SocketIO's threading backend is the sole async mode. Leaving the
# origin option unset uses its same-origin policy; explicit origins are exact.
socketio_options = {"async_mode": "threading"}
if CORS_ALLOWED_ORIGINS:
    socketio_options["cors_allowed_origins"] = list(CORS_ALLOWED_ORIGINS)
socketio = SocketIO(app, **socketio_options)
wsgi_app = WSGIApp(socketio.server, app.wsgi_app)

_analysis_cache = OrderedDict()
_rate_windows = defaultdict(deque)


@lru_cache(maxsize=1)
def get_pipeline():
    from artifacts import load_models

    models = load_models(MODEL_DIR)
    return AnalysisPipeline(models=models)


@app.before_request
def restrict_origin():
    origin = request.headers.get("Origin")
    if not origin:
        return None
    origin = origin.rstrip("/")
    same_origin = f"{request.scheme}://{request.host}".rstrip("/")
    if origin not in {same_origin, *CORS_ALLOWED_ORIGINS}:
        abort(403, description="This origin is not allowed to use the analysis API.")
    return None


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    same_origin = f"{request.scheme}://{request.host}".rstrip("/")
    if origin and origin in {same_origin, *CORS_ALLOWED_ORIGINS}:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def dashboard():
    try:
        report = json.loads((BASE_DIR / "reports" / "anomaly_evaluation.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report = {}
    return render_template(
        "monitor.html",
        public_host=os.environ.get("DEMO_PUBLIC_HOST", "false").lower() == "true",
        anomaly_report=report,
    )


@app.get("/healthz")
def healthz():
    try:
        get_pipeline()
    except (ArtifactError, OSError, ValueError) as exc:
        return jsonify({"status": "not_ready", "reason": str(exc)}), 503
    return jsonify({"status": "ok", "engine": "packet-metadata", "max_upload_bytes": MAX_UPLOAD_BYTES})


@app.get("/sample/<name>")
def sample_capture(name):
    allowed = {"normal.pcap", "with_attacks.pcap"}
    if name not in allowed:
        abort(404)
    path = SAMPLE_DIR / name
    if not path.is_file():
        abort(404)
    return send_file(path, mimetype="application/vnd.tcpdump.pcap", as_attachment=True,
                     download_name=name, max_age=0)


@app.post("/analyze")
def analyze_upload():
    limited = _apply_rate_limit()
    if limited:
        return limited
    uploaded, error = _get_upload()
    if error:
        return error
    try:
        result = get_pipeline().analyze(uploaded.read(), filename=uploaded.filename or "capture.pcap")
    except CaptureError as exc:
        app.logger.info(json.dumps({"event": "analysis_rejected", "reason": "invalid_capture"}))
        return jsonify({"error": str(exc)}), 400
    except AnalysisError as exc:
        app.logger.info(json.dumps({"event": "analysis_rejected", "reason": "no_flows"}))
        return jsonify({"error": str(exc)}), 422
    except ArtifactError as exc:
        app.logger.error(json.dumps({"event": "model_unavailable", "reason": str(exc)}))
        return jsonify({"error": "The checked model bundle is unavailable. Restore the model files from the project ZIP."}), 503
    except Exception:
        app.logger.exception(json.dumps({"event": "analysis_failed", "reason": "internal_error"}))
        return jsonify({"error": "The capture could not be analyzed. Try a supported PCAP or PCAPNG file."}), 500
    _cache_result(result)
    app.logger.info(json.dumps({
        "event": "analysis_complete",
        "flow_count": result["summary"]["flow_count"],
        "anomaly_count": result["summary"]["anomaly_count"],
        "packets_read": result["summary"]["packets_read"],
        "truncated": result["summary"]["truncated"],
    }))
    return jsonify(_result_overview(result))


@app.post("/replay")
def replay_upload():
    limited = _apply_rate_limit()
    if limited:
        return limited
    uploaded, error = _get_upload()
    if error:
        return error
    try:
        result = get_pipeline().analyze(uploaded.read(), filename=uploaded.filename or "capture.pcap")
    except (CaptureError, AnalysisError) as exc:
        return jsonify({"error": str(exc)}), 400
    except ArtifactError:
        return jsonify({"error": "The checked model bundle is unavailable."}), 503
    except Exception:
        app.logger.exception(json.dumps({"event": "replay_failed", "reason": "internal_error"}))
        return jsonify({"error": "The capture could not be prepared for replay."}), 500
    _cache_result(result)
    try:
        speed = min(8.0, max(0.25, float(request.args.get("speed", "1"))))
    except ValueError:
        speed = 1.0
    app.logger.info(json.dumps({"event": "replay_started", "flow_count": len(result["flows"])}))

    def generate_events():
        yield _ndjson({"event": "start", "analysis_id": result["analysis_id"],
                       "summary": result["summary"], "mix": result["mix"]})
        delay = 0.04 / speed
        replay_flows = sorted(result["flows"], key=lambda flow: flow["start_time"])
        for index, flow in enumerate(replay_flows, 1):
            yield _ndjson({"event": "flow", "index": index,
                           "total": len(replay_flows), "flow": _flow_overview(flow)})
            time.sleep(delay)
        yield _ndjson({"event": "complete", "analysis_id": result["analysis_id"]})

    return Response(stream_with_context(generate_events()), mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.get("/flow/<analysis_id>/<flow_id>")
def flow_detail(analysis_id, flow_id):
    details = _get_cached_detail(analysis_id, flow_id)
    if details is None:
        return jsonify({"error": "Flow details expired or not found. Upload the capture again."}), 404
    return Response(details, mimetype="application/json", headers={"Cache-Control": "no-store"})


@app.route("/export", methods=["GET", "POST"])
def export_analysis():
    export_options = request.get_json(silent=True) if request.method == "POST" else {}
    export_options = export_options or {}
    result = _get_cached_result(
        export_options.get("analysis_id", "") if request.method == "POST"
        else request.args.get("analysis_id", "")
    )
    if result is None:
        return jsonify({"error": "Analysis expired or not found. Upload the capture again."}), 404
    fmt = str(export_options.get("format", "json") if request.method == "POST"
              else request.args.get("format", "json")).lower()
    reviews = _valid_reviews(result, export_options.get("reviews", {}))
    if fmt == "json":
        body = json.dumps(_result_with_reviews(result, reviews), indent=2, ensure_ascii=False) + "\n"
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=traffic-analysis.json"})
    if fmt == "csv":
        output = StringIO(newline="")
        columns = ["flow_id", "score", "severity", "prediction", "confidence", "protocol",
                   "packets", "duration_seconds", "bytes", "reasons", "acknowledged", "dismissed", "note"]
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for flow in result["flows"]:
            writer.writerow({
                "flow_id": flow["flow_id"], "score": flow["score"],
                "severity": flow["severity"], "prediction": flow["label_name"],
                "confidence": flow["confidence"], "protocol": flow["protocol"],
                "packets": flow["packet_count"], "duration_seconds": flow["duration"],
                "bytes": flow["bytes"], "reasons": " | ".join(flow["reasons"]),
                "acknowledged": reviews.get(flow["flow_id"], {}).get("acknowledged", False),
                "dismissed": reviews.get(flow["flow_id"], {}).get("dismissed", False),
                "note": reviews.get(flow["flow_id"], {}).get("note", ""),
            })
        return Response(output.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=traffic-alerts.csv"})
    if fmt == "summary":
        return Response(_summary_html(result, reviews), mimetype="text/html",
                        headers={"Content-Disposition": "attachment; filename=incident-summary.html"})
    return jsonify({"error": "Choose format=csv, json, or summary."}), 400


@app.errorhandler(RequestEntityTooLarge)
def upload_too_large(_error):
    return jsonify({"error": "Capture exceeds the 25 MB upload limit."}), 413


@app.errorhandler(403)
def forbidden_origin(error):
    if request.path.startswith(("/analyze", "/replay", "/export")):
        return jsonify({"error": "This origin is not allowed to use the analysis API."}), 403
    return error


def _get_upload():
    uploaded = request.files.get("capture") or request.files.get("file")
    if uploaded is None:
        return None, (jsonify({"error": "Select a PCAP or PCAPNG capture file."}), 400)
    filename = (uploaded.filename or "").replace("\\", "/").split("/")[-1]
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return None, (jsonify({"error": "Supported file types are .pcap, .pcapng, and .cap."}), 415)
    uploaded.stream.seek(0, 2)
    file_size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    if file_size > MAX_UPLOAD_BYTES:
        return None, (jsonify({"error": "Capture exceeds the 25 MB upload limit."}), 413)
    return uploaded, None


def _apply_rate_limit():
    now = time.monotonic()
    # The address is used only as an in-memory key; it is never logged or saved.
    key = request.remote_addr or "unknown"
    window = _rate_windows[key]
    while window and now - window[0] >= RATE_LIMIT_WINDOW:
        window.popleft()
    if len(window) >= RATE_LIMIT_REQUESTS:
        response = jsonify({"error": "Too many analysis requests. Wait a minute and try again."})
        response.status_code = 429
        response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW)
        return response
    window.append(now)
    if len(_rate_windows) > 1024:
        for stale_key in list(_rate_windows)[:256]:
            if not _rate_windows[stale_key] or now - _rate_windows[stale_key][-1] > RATE_LIMIT_WINDOW:
                _rate_windows.pop(stale_key, None)
    return None


def _cache_result(result):
    overview = zlib.compress(
        json.dumps(_result_overview(result), separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        level=1,
    )
    flow_indices = {}
    details = []
    for index, flow in enumerate(result["flows"]):
        flow_indices[flow["flow_id"]] = index
        detail = {"features": flow["features"], "packet_trace": flow["packet_trace"]}
        details.append(zlib.compress(
            json.dumps(detail, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            level=1,
        ))
    _analysis_cache[result["analysis_id"]] = (time.monotonic(), overview, flow_indices, details)
    _analysis_cache.move_to_end(result["analysis_id"])
    while (len(_analysis_cache) > RESULT_CACHE_SIZE
           or sum(_cache_entry_size(entry) for entry in _analysis_cache.values()) > RESULT_CACHE_MAX_BYTES):
        _analysis_cache.popitem(last=False)


def _cache_entry_size(entry):
    return len(entry[1]) + sum(map(len, entry[3]))


def _get_cache_entry(analysis_id):
    value = _analysis_cache.get(analysis_id)
    if not value:
        return None
    created, _, _, _ = value
    if time.monotonic() - created > RESULT_CACHE_TTL:
        _analysis_cache.pop(analysis_id, None)
        return None
    return value


def _get_cached_result(analysis_id):
    value = _get_cache_entry(analysis_id)
    if not value:
        return None
    _, overview, _, _ = value
    try:
        return json.loads(zlib.decompress(overview))
    except (ValueError, zlib.error):
        return None


def _get_cached_detail(analysis_id, flow_id):
    value = _get_cache_entry(analysis_id)
    if not value:
        return None
    _, _, flow_indices, details = value
    index = flow_indices.get(flow_id)
    if index is None:
        return None
    try:
        return zlib.decompress(details[index])
    except zlib.error:
        return None


def _ndjson(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n"


def _valid_reviews(result, reviews):
    if not isinstance(reviews, dict):
        return {}
    known_flows = {flow["flow_id"] for flow in result["flows"]}
    clean = {}
    for flow_id, state in reviews.items():
        if flow_id not in known_flows or not isinstance(state, dict):
            continue
        clean[flow_id] = {
            "acknowledged": bool(state.get("acknowledged", False)),
            "dismissed": bool(state.get("dismissed", False)),
            "note": str(state.get("note", ""))[:500],
        }
    return clean


def _result_with_reviews(result, reviews):
    document = _result_overview(result)
    document["flows"] = [
        {**_flow_overview(flow), "review": reviews.get(flow["flow_id"], {
            "acknowledged": False, "dismissed": False, "note": "",
        })}
        for flow in result["flows"]
    ]
    return document


def _flow_overview(flow):
    return {key: value for key, value in flow.items()
            if key not in {"features", "packet_trace"}}


def _result_overview(result):
    document = dict(result)
    document["flows"] = [_flow_overview(flow) for flow in result["flows"]]
    return document


def _summary_html(result, reviews=None):
    reviews = reviews or {}
    summary = result["summary"]
    title = "Packet traffic incident summary"
    highest = [flow for flow in result["flows"] if flow["severity"] in {"medium", "high"}][:8]
    alert_rows = []
    for flow in highest:
        review = reviews.get(flow["flow_id"], {})
        state = "Dismissed" if review.get("dismissed") else "Acknowledged" if review.get("acknowledged") else "Unreviewed"
        values = (
            flow["severity"].upper(), flow["score"], flow["label_name"],
            "; ".join(flow["reasons"]), flow["packet_count"], flow["bytes"],
            state, review.get("note", ""),
        )
        alert_rows.append("<tr>" + "".join(
            f"<td>{html.escape(str(value))}</td>" for value in values
        ) + "</tr>")
    alert_rows = "".join(alert_rows) or '<tr><td colspan="8">No medium or high severity flows found.</td></tr>'
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{title}</title><style>body{{font:15px/1.5 system-ui,sans-serif;color:#17283a;max-width:900px;margin:36px auto;padding:0 22px}}h1{{font-size:30px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{border:1px solid #dbe3eb;border-radius:12px;padding:15px}}.card strong{{display:block;font-size:24px}}table{{border-collapse:collapse;width:100%;margin-top:22px}}th,td{{border-bottom:1px solid #dbe3eb;text-align:left;padding:9px;vertical-align:top}}th{{background:#f2f5f8}}.note{{color:#526478}}@media print{{body{{margin:12mm auto}}}}</style>
<h1>{title}</h1><p class="note">{html.escape(result['filename'])} · {html.escape(result['created_at'])} · Packet metadata only</p>
<div class="grid"><div class="card">Flows<strong>{summary['flow_count']:,}</strong></div><div class="card">Alerts<strong>{summary['anomaly_count']:,}</strong></div><div class="card">High severity<strong>{summary['high_severity_count']:,}</strong></div><div class="card">Packets<strong>{summary['packets_read']:,}</strong></div></div>
<h2>Top reason</h2><p>{html.escape(summary['top_reason'])}</p><h2>Highest scoring alerts</h2>
<table><thead><tr><th>Severity</th><th>Score</th><th>Class</th><th>Reason</th><th>Packets</th><th>Bytes</th><th>Review state</th><th>Note</th></tr></thead><tbody>{alert_rows}</tbody></table>
<p class="note">The labels are traffic-pattern estimates. This report does not prove malicious intent. Payloads were not inspected.</p></html>"""


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    print(f"Open http://127.0.0.1:{port} for the local packet monitor.")
    socketio.run(app, host="127.0.0.1", port=port, debug=False, allow_unsafe_werkzeug=True)
