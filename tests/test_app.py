import json
from io import BytesIO
from unittest.mock import patch

import app as web_app
from tests.pcap_helpers import make_pcap, packet


def _upload(client, endpoint="/analyze", filename="tiny.pcap", body=None, **kwargs):
    return client.post(
        endpoint,
        data={"capture": (BytesIO(body or make_pcap()), filename)},
        content_type="multipart/form-data",
        **kwargs,
    )


def setup_function():
    web_app._analysis_cache.clear()
    web_app._rate_windows.clear()


def test_dashboard_is_same_origin_and_self_hosted():
    client = web_app.app.test_client()
    response = client.get("/")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "packet metadata monitor" in body.lower()
    assert "monitor.js" in body
    assert "cdn." not in body.lower()
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert web_app.socketio.server.async_mode == "threading"


def test_upload_type_and_malformed_capture_errors_are_friendly():
    client = web_app.app.test_client()
    unsupported = _upload(client, filename="notes.txt")
    malformed = _upload(client, filename="broken.pcap", body=b"invalid pcap")

    assert unsupported.status_code == 415
    assert "Supported file types" in unsupported.json["error"]
    assert malformed.status_code == 400
    assert "capture" in malformed.json["error"].lower()


def test_analysis_and_exports_include_local_review_notes_without_network_identifiers():
    client = web_app.app.test_client()
    # One small-packet, high-rate flow: the fixed dos_burst rule flags it whatever
    # anomaly model is installed, so the summary always lists it.
    burst = make_pcap([
        packet("192.0.2.1", "198.51.100.1", 40_000, 443, 1_700_000_000.0 + i * 0.001, 60)
        for i in range(150)
    ])
    analyzed = _upload(client, body=burst)
    assert analyzed.status_code == 200, analyzed.get_data(as_text=True)
    result = analyzed.json
    assert result["summary"]["flow_count"] == 1
    flow = result["flows"][0]
    assert "features" not in flow and "packet_trace" not in flow
    assert "client_ip" not in flow and "server_ip" not in flow
    assert "192.0.2.1" not in analyzed.get_data(as_text=True)

    detail = client.get(f"/flow/{result['analysis_id']}/{flow['flow_id']}")
    assert detail.status_code == 200
    assert "packet_count" in detail.json["features"]
    assert detail.json["packet_trace"]
    assert client.get(f"/flow/{result['analysis_id']}/unknown").status_code == 404

    reviews = {flow["flow_id"]: {"acknowledged": True, "note": "<script>alert(1)</script>"}}
    json_export = client.post("/export", json={
        "analysis_id": result["analysis_id"], "format": "json", "reviews": reviews,
    })
    csv_export = client.post("/export", json={
        "analysis_id": result["analysis_id"], "format": "csv", "reviews": reviews,
    })
    summary_export = client.post("/export", json={
        "analysis_id": result["analysis_id"], "format": "summary", "reviews": reviews,
    })

    exported = json.loads(json_export.get_data(as_text=True))
    assert exported["flows"][0]["review"]["acknowledged"]
    assert "features" not in exported["flows"][0]
    assert "packet_trace" not in exported["flows"][0]
    assert "<script>alert(1)</script>" in csv_export.get_data(as_text=True)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in summary_export.get_data(as_text=True)
    assert summary_export.headers["Content-Disposition"].endswith("incident-summary.html")


def test_replay_streams_ndjson_flow_events():
    client = web_app.app.test_client()
    with patch("app.time.sleep", return_value=None):
        response = _upload(client, endpoint="/replay")

    assert response.status_code == 200
    assert response.mimetype == "application/x-ndjson"
    events = [json.loads(line) for line in response.get_data(as_text=True).splitlines()]
    assert [event["event"] for event in events] == ["start", "flow", "complete"]
    assert "packet_trace" not in events[1]["flow"]
    assert "features" not in events[1]["flow"]


def test_foreign_origin_is_blocked_and_rate_limit_is_bounded():
    client = web_app.app.test_client()
    blocked = client.post("/analyze", headers={"Origin": "https://attacker.example"})
    assert blocked.status_code == 403

    for _ in range(web_app.RATE_LIMIT_REQUESTS):
        assert client.post("/analyze").status_code == 400
    limited = client.post("/analyze")
    assert limited.status_code == 429
    assert limited.headers["Retry-After"] == "60"


def test_summary_reports_low_confidence_share():
    client = web_app.app.test_client()
    result = _upload(client).get_json()
    share = result["summary"]["low_confidence_share"]
    assert 0.0 <= share <= 1.0
