"""Optional local-only terminal capture mode; the hosted app never sniffs."""

from __future__ import annotations

import argparse
import json
from hashlib import sha256

import numpy as np
from scapy.all import IP, TCP, UDP, IPv6, sniff

from anomaly import AnomalyDetector, load_config
from artifacts import load_models
from features import extract_features, features_to_row
from flows import FlowTable, flow_key
from pcap_reader import MAX_CAPTURE_FLOWS, MAX_CAPTURE_PACKETS, FlowRecord


def run_live(interface=None, duration=60):
    (classifier, scaler, encoder, anomaly_model, anomaly_scaler,
     _classifier_metadata, anomaly_metadata) = load_models()
    table = FlowTable()
    packet_count = 0

    def on_packet(packet):
        nonlocal packet_count
        packet_count += 1
        if packet_count > MAX_CAPTURE_PACKETS:
            return
        if IP in packet:
            network = packet[IP]
        elif IPv6 in packet:
            network = packet[IPv6]
        else:
            return
        if TCP in packet:
            protocol, source_port, destination_port = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
        elif UDP in packet:
            protocol, source_port, destination_port = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
        else:
            return
        source, destination = str(network.src), str(network.dst)
        key = flow_key(source, destination, source_port, destination_port, protocol)
        if key not in table.flows and len(table.flows) >= MAX_CAPTURE_FLOWS:
            return
        flow = table.get_or_create(source, destination, source_port, destination_port, protocol)
        direction = table.direction_for(flow, source, source_port)
        flow.add_packet(len(packet), direction, float(packet.time))
        table.touch_concurrency(flow)

    print(json.dumps({
        "event": "capture_started",
        "duration_seconds": duration,
        "interface": interface or "default",
        "notice": "Local-only; packet payloads are not inspected.",
    }))
    sniff(prn=on_packet, timeout=duration, store=False, iface=interface,
          stop_filter=lambda _packet: packet_count >= MAX_CAPTURE_PACKETS)

    records = []
    for flow in table.all_flows():
        features = extract_features(flow.packets, proto=flow.proto,
                                    server_port=flow.server_port,
                                    max_concurrent_flows=flow.max_concurrent_flows)
        if features is None:
            continue
        flow_id = sha256(repr(flow.key).encode("utf-8")).hexdigest()[:12]
        records.append(FlowRecord(flow_id, flow, features))
    detector = AnomalyDetector(anomaly_model, anomaly_scaler,
                               anomaly_metadata, load_config())
    alerts = detector.score_flows(records)
    rows = np.asarray([features_to_row(record.features) for record in records], dtype=float)
    if len(rows):
        probabilities = classifier.predict_proba(scaler.transform(rows))
        for record, alert, probability in zip(records, alerts, probabilities, strict=True):
            class_index = int(probability.argmax())
            print(json.dumps({
                "event": "flow_alert",
                "flow_id": record.flow_id,
                "anomaly_score": alert["score"],
                "severity": alert["severity"],
                "classification": str(encoder.inverse_transform([class_index])[0]),
                "confidence": round(float(probability[class_index]), 3),
                "reasons": alert["reasons"],
                "packets": int(record.features["packet_count"]),
            }, separators=(",", ":")))
    print(json.dumps({"event": "capture_complete", "packets": packet_count,
                      "flows": len(records)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", default=None, help="Local network interface to sniff")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    args = parser.parse_args()
    run_live(interface=args.iface, duration=max(1, args.duration))


if __name__ == "__main__":
    main()
