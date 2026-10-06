import pytest

from pipeline import MIN_CLASSIFY_PACKETS, AnalysisPipeline


@pytest.fixture(scope="module")
def result():
    with open("sample_data/with_attacks.pcap", "rb") as handle:
        return AnalysisPipeline().analyze(handle.read(), filename="with_attacks.pcap")


def test_short_flows_are_reported_but_not_classified(result):
    short = [flow for flow in result["flows"] if not flow["classifiable"]]
    assert short, "the attack sample contains 2-packet scan probes"
    assert all(flow["packet_count"] < MIN_CLASSIFY_PACKETS for flow in short)
    assert all(flow["label"] == "too_short" and not flow["needs_review"] for flow in short)
    # they still get anomaly scores
    assert all("score" in flow and "severity" in flow for flow in short)


def test_mix_and_low_confidence_share_ignore_short_flows(result):
    summary = result["summary"]
    classifiable = [flow for flow in result["flows"] if flow["classifiable"]]
    assert summary["classifiable_count"] == len(classifiable)
    assert summary["too_short_count"] == len(result["flows"]) - len(classifiable)
    assert sum(item["flows"] for item in result["mix"]) == len(classifiable)
    expected = sum(flow["needs_review"] for flow in classifiable) / len(classifiable)
    assert summary["low_confidence_share"] == pytest.approx(expected, abs=1e-4)
    assert sum(item["percent"] for item in result["mix"]) == pytest.approx(100, abs=0.5)
