from flows import FlowTable, flow_key


def test_bidirectional_packets_share_one_flow_and_direction():
    table = FlowTable()
    flow = table.get_or_create("192.0.2.1", "198.51.100.1", 40000, 443, "TCP")
    reverse = table.get_or_create("198.51.100.1", "192.0.2.1", 443, 40000, "TCP")

    assert reverse is flow
    assert len(table.all_flows()) == 1
    assert table.direction_for(flow, "192.0.2.1", 40000) == "up"
    assert table.direction_for(flow, "198.51.100.1", 443) == "down"
    assert flow_key("192.0.2.1", "198.51.100.1", 40000, 443, "TCP") == flow_key(
        "198.51.100.1", "192.0.2.1", 443, 40000, "TCP"
    )


def test_flow_start_and_duration_use_packet_timestamps():
    table = FlowTable()
    flow = table.get_or_create("192.0.2.1", "198.51.100.1", 40000, 443, "TCP")
    flow.add_packet(60, "up", 100.0)
    flow.add_packet(80, "down", 100.5)

    assert flow.start_time == 100.0
    assert flow.duration == 0.5
    assert flow.packet_count == 2

