"""
qos.py
------
Maps a predicted traffic class to a QoS decision. This is the "so
what" step -- turning a classification into an actionable traffic-
shaping recommendation, the way a real campus/ISP router would.

The generated `tc`/`iptables` snippets are advisory strings only --
this module does not touch your system's actual network stack.
"""

# priority: lower number = higher priority (gets bandwidth first)
QOS_POLICY = {
    "video_call": {
        "priority": 1,
        "action": "prioritize",
        "reason": "Real-time, latency-sensitive -- protect it from queueing delay.",
    },
    "gaming": {
        "priority": 1,
        "action": "prioritize",
        "reason": "Latency/jitter-sensitive interactive traffic.",
    },
    "streaming": {
        "priority": 2,
        "action": "standard",
        "reason": "Buffered playback -- tolerant of some jitter, needs steady throughput.",
    },
    "browsing": {
        "priority": 2,
        "action": "standard",
        "reason": "Bursty but short-lived, low overall volume.",
    },
    "download": {
        "priority": 3,
        "action": "deprioritize",
        "reason": "Bulk transfer, not latency sensitive -- safe to throttle under contention.",
    },
    "unknown": {
        "priority": 2,
        "action": "standard",
        "reason": "Not enough confidence to treat specially; default treatment.",
    },
}


def qos_decision(predicted_label: str, confidence: float, flow_five_tuple: tuple):
    """
    Returns a dict describing the recommended QoS treatment for a
    classified flow, plus an example tc/iptables command a real
    deployment could execute (not run automatically here).
    """
    policy = QOS_POLICY.get(predicted_label, QOS_POLICY["unknown"])
    client_ip, client_port, server_ip, server_port, proto = flow_five_tuple

    # Example DSCP marking command an operator could actually run.
    # Priority tiers map to DSCP classes: EF (expedited forwarding) for
    # priority 1, AF31 for priority 2, and CS1 (scavenger/bulk) for priority 3.
    dscp_map = {1: "ef", 2: "af31", 3: "cs1"}
    dscp = dscp_map.get(policy["priority"], "af31")

    example_cmd = (
        f"iptables -t mangle -A OUTPUT -p {proto.lower()} "
        f"--sport {client_port} -j DSCP --set-dscp-class {dscp}"
    )

    return {
        "label": predicted_label,
        "confidence": round(confidence, 3),
        "priority": policy["priority"],
        "action": policy["action"],
        "reason": policy["reason"],
        "suggested_command": example_cmd,
        "flow": {
            "client": f"{client_ip}:{client_port}",
            "server": f"{server_ip}:{server_port}",
            "proto": proto,
        },
    }
