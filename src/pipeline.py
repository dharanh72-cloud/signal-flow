"""Single privacy-preserving analysis pipeline for classifier and anomaly results."""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

import numpy as np

from anomaly import AnomalyDetector, load_config
from artifacts import load_models
from features import features_to_row
from pcap_reader import MAX_CAPTURE_FLOWS, MAX_CAPTURE_PACKETS, read_capture

CLASS_NAMES = {
    "video_call": "Video call",
    "streaming": "Streaming",
    "download": "Download",
    "browsing": "Browsing",
    "gaming": "Gaming",
    "needs_review": "Needs review",
    "too_short": "Too short to classify",
    "unknown": "Unknown",
}


# The classifier was trained only on flows with at least this many packets, so shorter
# flows (port-scan probes, lone DNS lookups) are reported but not classified.
MIN_CLASSIFY_PACKETS = 6


class AnalysisError(ValueError):
    """The capture is valid but cannot produce a useful analysis."""


class AnalysisPipeline:
    def __init__(self, models=None):
        (self.classifier, self.classifier_scaler, self.encoder,
         anomaly_model, anomaly_scaler, self.classifier_metadata,
         anomaly_metadata) = models or load_models()
        self.detector = AnomalyDetector(anomaly_model, anomaly_scaler,
                                        anomaly_metadata, load_config())
        self.review_threshold = float(
            self.classifier_metadata.get("review_threshold", 0.40)
        )

    def analyze(self, capture_bytes: bytes, *, filename="capture.pcap") -> dict:
        capture = read_capture(
            capture_bytes, max_packets=MAX_CAPTURE_PACKETS, max_flows=MAX_CAPTURE_FLOWS
        )
        if not capture.flows:
            raise AnalysisError(
                "No TCP or UDP flows with at least two packets were found. "
                "Check that the file contains supported IP traffic."
            )

        rows = np.asarray(
            [features_to_row(record.features) for record in capture.flows], dtype=float
        )
        probabilities = self.classifier.predict_proba(
            self.classifier_scaler.transform(rows)
        )
        best_indices = probabilities.argmax(axis=1)
        labels = self.encoder.inverse_transform(best_indices)
        confidences = probabilities.max(axis=1)
        anomaly_rows = self.detector.score_flows(capture.flows)

        flows = []
        for record, candidate, confidence, alert in zip(
            capture.flows, labels, confidences, anomaly_rows, strict=True
        ):
            classifiable = int(record.features["packet_count"]) >= MIN_CLASSIFY_PACKETS
            if not classifiable:
                final_label = "too_short"
            elif confidence >= self.review_threshold:
                final_label = str(candidate)
            else:
                final_label = "needs_review"
            packets = sorted(record.flow.packets, key=lambda packet: packet.timestamp)
            origin = packets[0].timestamp if packets else 0.0
            trace = [
                {
                    "time": round(packet.timestamp - origin, 4),
                    "size": int(packet.size),
                    "direction": packet.direction,
                }
                for packet in packets[::max(1, len(packets) // 80)]
            ][:80]
            flows.append({
                "flow_id": record.flow_id,
                "label": final_label,
                "label_name": CLASS_NAMES.get(final_label, final_label.replace("_", " ").title()),
                "candidate": str(candidate),
                "candidate_name": CLASS_NAMES.get(str(candidate), str(candidate).replace("_", " ").title()),
                "confidence": round(float(confidence), 4),
                "needs_review": final_label == "needs_review",
                "classifiable": classifiable,
                "protocol": record.flow.proto,
                "packet_count": int(record.features["packet_count"]),
                "duration": round(float(record.features["duration"]), 4),
                "bytes": int(record.features["total_bytes"]),
                "score": int(alert["score"]),
                "severity": alert["severity"],
                "reasons": alert["reasons"],
                "rule_hits": alert["rule_hits"],
                "features": record.features,
                "packet_trace": trace,
                "start_time": record.flow.start_time,
            })

        return self._summarize(
            capture, flows, filename=filename,
            analysis_id=uuid.uuid4().hex[:16],
        )

    def _summarize(self, capture, flows, *, filename, analysis_id):
        class_totals = defaultdict(lambda: {"flows": 0, "bytes": 0, "needs_review": 0})
        scores = [flow["score"] for flow in flows]
        classifiable = [flow for flow in flows if flow["classifiable"]]
        for flow in classifiable:
            # Keep the top class estimate useful for the traffic mix while the
            # flow table marks low-confidence estimates as needing review.
            target = class_totals[flow["candidate"]]
            target["flows"] += 1
            target["bytes"] += flow["bytes"]
            target["needs_review"] += int(flow["needs_review"])
        total_bytes = sum(flow["bytes"] for flow in flows)
        classified_bytes = sum(flow["bytes"] for flow in classifiable)
        mix = [
            {
                "key": key,
                "name": CLASS_NAMES.get(key, key.replace("_", " ").title()),
                "flows": values["flows"],
                "bytes": values["bytes"],
                "needs_review": values["needs_review"],
                "percent": round(100 * values["bytes"] / max(classified_bytes, 1), 2),
            }
            for key, values in sorted(
                class_totals.items(), key=lambda item: item[1]["bytes"], reverse=True
            )
        ]
        scored = sorted(flows, key=lambda flow: (flow["score"], flow["bytes"]), reverse=True)
        anomalous = [flow for flow in flows if flow["severity"] != "low"]
        timestamps = [flow["start_time"] for flow in flows]
        time_buckets = _time_buckets(flows, timestamps)
        summary = {
            "flow_count": len(flows),
            "packets_read": capture.packets_read,
            "transport_packets": capture.transport_packets,
            "total_bytes": total_bytes,
            "anomaly_count": len(anomalous),
            "high_severity_count": sum(flow["severity"] == "high" for flow in flows),
            "medium_severity_count": sum(flow["severity"] == "medium" for flow in flows),
            "highest_severity": scored[0]["severity"] if scored else "low",
            "top_reason": next((reason for flow in scored for reason in flow["reasons"]),
                               "No standout anomaly reason."),
            "needs_review_count": sum(flow["needs_review"] for flow in flows),
            "classifiable_count": len(classifiable),
            "too_short_count": len(flows) - len(classifiable),
            "low_confidence_share": round(
                sum(flow["needs_review"] for flow in classifiable) / max(len(classifiable), 1), 4
            ),
            "truncated": capture.truncated,
            "skipped_flows": capture.skipped_flows,
            "bytes_read": capture.bytes_read,
            "thresholds": {
                "medium": int(self.detector.config["engine"]["medium_severity"]),
                "high": int(self.detector.config["engine"]["high_severity"]),
            },
            "review_threshold": self.review_threshold,
        }
        deltas = [max(0.0, flow["start_time"] - min(timestamps)) for flow in flows] if timestamps else []
        max_time = max(deltas, default=0.0)
        distribution = Counter(min(9, int(score // 10)) for score in scores)
        return {
            "analysis_id": analysis_id,
            "created_at": datetime.now(UTC).isoformat(),
            "filename": _safe_display_filename(filename),
            "summary": summary,
            "mix": mix,
            "time_series": time_buckets,
            "score_distribution": [
                {"range": f"{bucket * 10}–{bucket * 10 + 9}", "count": distribution[bucket]}
                for bucket in range(10)
            ],
            "flows": sorted(flows, key=lambda flow: (flow["score"], flow["bytes"]), reverse=True),
            "duration_seconds": round(max_time, 2),
            "parser": {
                "packets_read": capture.packets_read,
                "transport_packets": capture.transport_packets,
                "skipped_flows": capture.skipped_flows,
                "truncated": capture.truncated,
            },
        }


def _time_buckets(flows, timestamps, count=20):
    if not timestamps:
        return []
    start, end = min(timestamps), max(timestamps)
    span = max(end - start, 1e-9)
    buckets = [{"label": i, "flows": 0, "anomalies": 0} for i in range(count)]
    for flow in flows:
        index = min(count - 1, int((flow["start_time"] - start) / span * count))
        buckets[index]["flows"] += 1
        if flow["severity"] != "low":
            buckets[index]["anomalies"] += 1
    return buckets


def _safe_display_filename(filename: str) -> str:
    # The filename is display-only and never reaches a filesystem or command.
    name = str(filename).replace("\\", "/").split("/")[-1]
    return name[:100] or "capture.pcap"
