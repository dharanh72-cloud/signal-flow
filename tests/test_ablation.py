import json
from pathlib import Path

from scripts.ablation import VARIANTS, evaluate_ablation, render_report

from pcap_reader import read_capture

SAMPLES = Path("sample_data")


def _attacker_ips():
    data = (SAMPLES / "with_attacks.pcap").read_bytes()
    truth = {f["flow_id"] for f in json.loads((SAMPLES / "with_attacks_labels.json").read_text())["flows"]
             if f["is_attack"]}
    return {r.flow.client_ip for r in read_capture(data).flows if r.flow_id in truth}


def test_variants_are_consistent_on_the_attack_sample():
    attackers = _attacker_ips()
    stats = evaluate_ablation((SAMPLES / "with_attacks.pcap").read_bytes(), attackers)
    assert stats["attack_flows"] > 0
    for variant in VARIANTS:
        c = stats["variants"][variant]
        assert c["tp"] + c["fn"] == stats["attack_flows"]
        assert c["fp"] + c["tn"] == stats["benign_flows"]
    rules, both = stats["variants"]["rules_only"], stats["variants"]["both"]
    assert rules["recall"] > 0.9
    # the dashboard score is never lower than the rules alone
    assert both["tp"] >= rules["tp"] and both["fp"] >= rules["fp"]
    assert stats["model_adds_tp"] == both["tp"] - rules["tp"]
    assert stats["model_adds_fp"] == both["fp"] - rules["fp"]


def test_benign_run_reports_false_alarms_only():
    stats = evaluate_ablation((SAMPLES / "normal.pcap").read_bytes(), set())
    assert stats["attack_flows"] == 0 and stats["benign_flows"] > 0
    assert stats["variants"]["both"]["recall"] is None
    assert stats["variants"]["both"]["false_alarm_rate"] <= 0.05
    report = render_report("normal.pcap", set(), stats)
    assert "no attack flows" in report and "Model only" in report and "Rules only" in report
