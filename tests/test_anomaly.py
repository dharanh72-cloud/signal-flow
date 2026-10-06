import copy

import pytest

from anomaly import AnomalyDetector, load_config, severity_for
from features import FEATURE_NAMES, extract_features
from flows import Flow, flow_key
from pcap_reader import FlowRecord


class IdentityScaler:
    def transform(self, values):
        return values


class FixedModel:
    def __init__(self, score=0.2):
        self.score = score

    def score_samples(self, values):
        return [self.score] * len(values)


def _record(source, server, source_port, server_port, protocol, packets):
    key = flow_key(source, server, source_port, server_port, protocol)
    flow = Flow(key, source, source_port, server, server_port, protocol)
    for timestamp, size, direction in packets:
        flow.add_packet(size, direction, timestamp)
    features = extract_features(flow.packets, proto=protocol, server_port=server_port)
    assert features is not None
    return FlowRecord("test-id", flow, features)


def _detector(score=0.2):
    metadata = {
        "feature_names": FEATURE_NAMES,
        "score_threshold_q01": 0.0,
        "score_min": -1.0,
        "feature_stats": {},
    }
    return AnomalyDetector(FixedModel(score), IdentityScaler(), metadata, load_config())


def test_port_scan_rule_uses_source_wide_distinct_destination_ports():
    source, server = "192.0.2.8", "198.51.100.8"
    records = [
        _record(source, server, 40_000 + index, 1000 + index, "TCP",
                [(10 + index * 0.1, 60, "up"), (10.02 + index * 0.1, 60, "down")])
        for index in range(10)
    ]

    alerts = _detector().score_flows(records)
    assert all(any(hit["code"] == "port_scan" for hit in alert["rule_hits"]) for alert in alerts)
    assert "distinct destination ports" in alerts[0]["reasons"][0]


def test_slow_scan_rule_uses_capture_wide_time_span():
    source, server = "192.0.2.9", "198.51.100.9"
    records = [
        _record(source, server, 41_000 + index, 2000 + index, "TCP",
                [(index * 13.1, 60, "up"), (index * 13.1 + 0.02, 60, "down")])
        for index in range(8)
    ]

    alerts = _detector().score_flows(records)
    assert all(any(hit["code"] == "slow_scan" for hit in alert["rule_hits"]) for alert in alerts)


def test_exfiltration_rule_flags_large_upload_with_tiny_download():
    packets = [(index * 0.1, 1400, "up") for index in range(40)]
    packets.insert(1, (0.02, 70, "down"))
    alert = _detector().score_flows([
        _record("192.0.2.10", "198.51.100.10", 42000, 443, "TCP", packets)
    ])[0]

    assert any(hit["code"] == "exfiltration" for hit in alert["rule_hits"])
    assert "Upload is" in alert["reasons"][0]


def test_dos_burst_rule_uses_packet_rate_and_count():
    packets = [(index * 0.0015, 66, "up") for index in range(180)]
    alert = _detector().score_flows([
        _record("192.0.2.11", "198.51.100.11", 43000, 80, "TCP", packets)
    ])[0]

    assert any(hit["code"] == "dos_burst" for hit in alert["rule_hits"])
    assert "Packet rate is" in alert["reasons"][0]


def test_beacon_rule_uses_small_regular_packets():
    packets = [(index * 0.5, 72, "down" if index % 6 == 5 else "up") for index in range(72)]
    alert = _detector().score_flows([
        _record("192.0.2.12", "198.51.100.12", 44000, 443, "TCP", packets)
    ])[0]

    assert any(hit["code"] == "beaconing" for hit in alert["rule_hits"])
    assert "regular intervals" in alert["reasons"][0]


def test_dns_tunnel_rule_flags_large_udp_port_53_uploads():
    packets = []
    for index in range(20):
        timestamp = index * 0.18
        packets.append((timestamp, 950, "up"))
        if index % 5 == 0:
            packets.append((timestamp + 0.035, 85, "down"))
    alert = _detector().score_flows([
        _record("192.0.2.13", "198.51.100.13", 45000, 53, "UDP", packets)
    ])[0]

    assert any(hit["code"] == "dns_tunnel" for hit in alert["rule_hits"])
    assert "port 53" in alert["reasons"][0]


def test_model_outlier_explanation_uses_feature_z_scores():
    config = copy.deepcopy(load_config())
    config["engine"]["zscore_threshold"] = 3
    metadata = {
        "feature_names": FEATURE_NAMES,
        "score_threshold_q01": 0.0,
        "score_min": -1.0,
        "feature_stats": {name: {"mean": 0.0, "std": 1.0} for name in FEATURE_NAMES},
    }
    detector = AnomalyDetector(FixedModel(-0.9), IdentityScaler(), metadata, config)
    record = _record("192.0.2.14", "198.51.100.14", 46000, 443, "TCP",
                     [(1.0, 100, "up"), (2.0, 100, "down")])

    alert = detector.score_flows([record])[0]
    assert alert["score"] > 0
    assert any("standard deviations from the normal mean" in reason for reason in alert["reasons"])


@pytest.mark.parametrize(("score", "expected"), [(0, "low"), (29, "low"), (30, "medium"), (59, "medium"), (60, "high"), (100, "high")])
def test_severity_bands(score, expected):
    assert severity_for(score, load_config()) == expected



def test_batched_model_scores_match_single_flow_scores():
    records = [
        _record("192.0.2.9", "198.51.100.9", 41000 + i, 443, "TCP",
                [(0.0, 100, "up"), (0.1 + i, 1200, "down"), (0.2 + i, 90, "up")])
        for i in range(3)
    ]
    detector = _detector(score=-0.5)
    batched = detector._model_scores(records)
    single = [detector._statistical_score(record.features)[1] for record in records]
    assert batched == single
    assert detector._model_scores([]) == []
