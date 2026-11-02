"""Flow-level anomaly scoring with a normal-only model and explainable rules."""

import tomllib
from collections import defaultdict
from pathlib import Path

import numpy as np

from features import FEATURE_NAMES

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "anomaly.toml"
FEATURE_EXPLANATIONS = {
    "bytes_per_sec": "byte rate",
    "packets_per_sec": "packet rate",
    "up_down_byte_ratio": "upload/download byte ratio",
    "up_down_packet_ratio": "upload/download packet ratio",
    "duration": "flow duration",
    "packet_count": "packet count",
    "iat_cv": "packet timing regularity",
    "pkt_size_mean": "average packet size",
    "max_concurrent_flows": "concurrent flow count",
}


def load_config(path=DEFAULT_CONFIG):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def severity_for(score: int, config: dict) -> str:
    if score >= config["engine"]["high_severity"]:
        return "high"
    if score >= config["engine"]["medium_severity"]:
        return "medium"
    return "low"


def max_distinct_in_window(events: list[tuple[float, int]], window: float) -> int:
    """Most distinct ports seen in any `window`-second span of (timestamp, port) events.

    A window of 0 or less means "the whole capture", which is the original behavior.
    """
    if not events:
        return 0
    events = sorted(events)
    if window <= 0:
        return len({port for _, port in events})
    counts: dict[int, int] = {}
    best = left = 0
    for timestamp, port in events:
        counts[port] = counts.get(port, 0) + 1
        while timestamp - events[left][0] > window:
            old_port = events[left][1]
            counts[old_port] -= 1
            if counts[old_port] == 0:
                del counts[old_port]
            left += 1
        best = max(best, len(counts))
    return best


class AnomalyDetector:
    """Combine Isolation Forest novelty with metadata-only attack rules."""

    def __init__(self, model, scaler, metadata: dict, config: dict | None = None):
        self.model = model
        self.scaler = scaler
        self.metadata = metadata
        self.config = config or load_config()
        if metadata.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Anomaly model feature list does not match this application.")

    def _model_scores(self, records: list) -> list[float]:
        """Score every flow with one batched Isolation Forest call (much faster than per-flow)."""
        if not records:
            return []
        rows = np.asarray(
            [[record.features[name] for name in FEATURE_NAMES] for record in records],
            dtype=float,
        )
        return [float(value) for value in self.model.score_samples(self.scaler.transform(rows))]

    def _statistical_score(
        self, features: dict, sample_score: float | None = None
    ) -> tuple[int, float, list[str]]:
        if sample_score is None:
            row = np.asarray([features[name] for name in FEATURE_NAMES], dtype=float).reshape(1, -1)
            sample_score = float(self.model.score_samples(self.scaler.transform(row))[0])
        threshold = float(self.metadata["score_threshold_q01"])
        minimum = float(self.metadata["score_min"])
        max_score = int(self.config["engine"]["model_max_score"])
        if sample_score >= threshold:
            return 0, sample_score, []
        spread = max(threshold - minimum, 1e-9)
        score = int(round(np.clip((threshold - sample_score) / spread, 0, 1) * max_score))

        stats = self.metadata.get("feature_stats", {})
        deviations = []
        for name in FEATURE_NAMES:
            stat = stats.get(name)
            if not stat:
                continue
            scale = max(float(stat["std"]), 1e-9)
            z_score = (float(features[name]) - float(stat["mean"])) / scale
            if abs(z_score) >= float(self.config["engine"]["zscore_threshold"]):
                deviations.append((abs(z_score), name, float(features[name]), z_score))
        deviations.sort(reverse=True)
        reasons = [
            f"{FEATURE_EXPLANATIONS.get(name, name.replace('_', ' '))} is "
            f"{value:.2f} ({z_score:+.1f} standard deviations from the normal mean)."
            for _, name, value, z_score in deviations[:3]
        ]
        if not reasons and score:
            reasons.append("The combined packet metadata is outside the normal-flow model.")
        return score, sample_score, reasons

    def _rule_hits(self, record, context):
        flow = record.flow
        features = record.features
        hits = []
        config = self.config

        scan = config["port_scan"]
        port_count = context["scan_ports_by_source"].get(flow.client_ip, 0)
        window = float(scan.get("window_seconds", 0))
        where = f"within {window:.0f} seconds" if window > 0 else "in this capture"
        if port_count >= scan["distinct_ports_medium"]:
            level = "many" if port_count >= scan["distinct_ports_high"] else "several"
            hits.append({
                "code": "port_scan",
                "name": "Port scan",
                "score": int(scan["score"]),
                "reason": f"This source contacted {port_count} distinct destination ports {where} ({level}).",
            })

        slow = config["slow_scan"]
        probe_ports = context["probe_ports_by_source"].get(flow.client_ip, 0)
        span = context["probe_span_by_source"].get(flow.client_ip, 0.0)
        if probe_ports >= slow["distinct_ports"] and span >= slow["minimum_span_seconds"]:
            hits.append({
                "code": "slow_scan",
                "name": "Slow port scan",
                "score": int(slow["score"]),
                "reason": f"Short connections reached {probe_ports} ports over {span:.0f} seconds.",
            })

        exfil = config["exfiltration"]
        upload_bytes = float(features["up_bytes"])
        ratio = float(features["up_down_byte_ratio"])
        if upload_bytes >= exfil["minimum_upload_bytes"] and ratio >= exfil["upload_download_ratio"]:
            hits.append({
                "code": "exfiltration",
                "name": "Possible data exfiltration",
                "score": int(exfil["score"]),
                "reason": f"Upload is {ratio:.1f}× download ({upload_bytes:,.0f} bytes up, {features['down_bytes']:,.0f} bytes down).",
            })

        dos = config["dos_burst"]
        packet_rate = float(features["packets_per_sec"])
        if (
            features["packet_count"] >= dos["minimum_packets"]
            and packet_rate >= dos["packets_per_second"]
            and features["pkt_size_mean"] <= dos.get("maximum_packet_size_mean", float("inf"))
        ):
            hits.append({
                "code": "dos_burst",
                "name": "High-rate packet burst",
                "score": int(dos["score"]),
                "reason": f"Packet rate is {packet_rate:.0f}/sec ({int(features['packet_count'])} packets in {features['duration']:.2f} seconds).",
            })

        beacon = config["beaconing"]
        if (
            features["packet_count"] >= beacon["minimum_packets"]
            and features["duration"] >= beacon["minimum_duration_seconds"]
            and features["pkt_size_mean"] <= beacon["maximum_packet_size_mean"]
            and features["iat_cv"] <= beacon["maximum_interarrival_cv"]
        ):
            hits.append({
                "code": "beaconing",
                "name": "Regular beacon-like traffic",
                "score": int(beacon["score"]),
                "reason": f"Small packets repeat at regular intervals (timing CV {features['iat_cv']:.3f} over {features['duration']:.0f} seconds).",
            })

        dns = config["dns_tunnel"]
        average_up_size = upload_bytes / max(float(features["up_packet_count"]), 1.0)
        if (
            flow.proto == "UDP"
            and flow.server_port == 53
            and features["packet_count"] >= dns["minimum_packets"]
            and upload_bytes >= dns["minimum_upload_bytes"]
            and average_up_size >= dns["maximum_average_upload_packet_bytes"]
        ):
            hits.append({
                "code": "dns_tunnel",
                "name": "Unusually large DNS flow",
                "score": int(dns["score"]),
                "reason": f"UDP port 53 carries {upload_bytes:,.0f} bytes upstream, averaging {average_up_size:.0f} bytes per outgoing packet.",
            })
        return hits

    def score_flows(self, records: list) -> list[dict]:
        """Score all flows together so source-wide port scans can be detected."""
        window = float(self.config["port_scan"].get("window_seconds", 0))
        probe_max = int(self.config["slow_scan"].get("probe_max_packets", 0))
        starts_by_source = defaultdict(list)
        probe_ports_by_source = defaultdict(set)
        probe_times_by_source = defaultdict(list)
        for record in records:
            flow = record.flow
            source = flow.client_ip
            starts_by_source[source].append((flow.start_time, flow.server_port))
            # Slow scans are made of short probe connections, not long conversations.
            if probe_max <= 0 or flow.packet_count <= probe_max:
                probe_ports_by_source[source].add(flow.server_port)
                probe_times_by_source[source].extend(
                    packet.timestamp for packet in flow.packets
                )
        context = {
            "scan_ports_by_source": {
                source: max_distinct_in_window(events, window)
                for source, events in starts_by_source.items()
            },
            "probe_ports_by_source": {
                source: len(ports) for source, ports in probe_ports_by_source.items()
            },
            "probe_span_by_source": {
                source: max(times) - min(times) if times else 0.0
                for source, times in probe_times_by_source.items()
            },
        }

        alerts = []
        blend = float(self.config["engine"]["rule_model_blend"])
        batch_scores = self._model_scores(records)
        for record, batch_score in zip(records, batch_scores, strict=True):
            model_score, raw_model_score, statistical_reasons = self._statistical_score(
                record.features, batch_score
            )
            rule_hits = self._rule_hits(record, context)
            top_rule_score = max((hit["score"] for hit in rule_hits), default=0)
            score = int(round(min(100, max(model_score, top_rule_score) + min(20, model_score * blend))))
            reasons = [hit["reason"] for hit in sorted(rule_hits, key=lambda hit: hit["score"], reverse=True)]
            if model_score:
                reasons.extend(statistical_reasons)
            alerts.append({
                "flow_id": record.flow_id,
                "score": score,
                "severity": severity_for(score, self.config),
                "rule_hits": rule_hits,
                "reasons": reasons[:4],
                "model_score": model_score,
                "model_raw_score": raw_model_score,
                "features": dict(record.features),
            })
        return alerts
