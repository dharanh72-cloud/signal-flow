from features import FEATURE_NAMES, extract_features
from flows import PacketRecord


def test_features_use_only_sizes_directions_and_timestamps():
    packets = [
        PacketRecord(1.0, 100, "up"),
        PacketRecord(1.5, 300, "down"),
        PacketRecord(2.0, 500, "up"),
    ]
    features = extract_features(packets, proto="UDP", server_port=53, max_concurrent_flows=2)

    assert len(features) == len(FEATURE_NAMES) == 34
    assert features["packet_count"] == 3
    assert features["duration"] == 1.0
    assert features["total_bytes"] == 900
    assert features["up_bytes"] == 600
    assert features["down_bytes"] == 300
    assert features["is_udp"] == 1.0
    assert features["is_well_known_port"] == 1.0
    assert features["max_concurrent_flows"] == 2


def test_single_packet_does_not_create_a_flow_vector():
    assert extract_features([PacketRecord(1.0, 60, "up")], proto="TCP", server_port=443) is None

