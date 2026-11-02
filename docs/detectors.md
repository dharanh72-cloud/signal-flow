# Detectors and thresholds

The detector scores each flow from 0 to 100. It combines a normal-only Isolation Forest score with capture-wide rules. A rule hit contributes its configured score; the model can add up to 40 points and a small blend bonus. Scores are capped at 100.

| Detector | Trigger | Default rule score | Common benign lookalikes |
| --- | --- | ---: | --- |
| Port scan | One source contacts at least 8 distinct destination ports within any 60-second window (`window_seconds`; 0 means the whole capture); 15 ports marks the stronger band in the explanation. | 84 | Service discovery, vulnerability scans, monitoring |
| Slow scan | At least 8 distinct ports reached by short connections (4 packets or fewer, `probe_max_packets`; 0 counts every flow) from one source, spread over 90 seconds or more. | 72 | Long maintenance checks, inventory tools |
| Possible exfiltration | At least 30,000 upstream frame bytes and an upstream/downstream byte ratio of at least 20. | 82 | Cloud backup, upload, synchronization |
| High-rate burst | At least 100 packets in a flow and at least 200 packets/second. | 78 | Short-lived load tests, busy media bursts |
| Beacon-like traffic | At least 12 packets over 30 seconds; mean frame size at most 180 bytes; inter-arrival coefficient of variation at most 0.05. | 70 | Keep-alives, telemetry, periodic health checks |
| Large UDP/53 flow | UDP destination port 53, at least 12 packets, at least 4,000 upstream frame bytes, and mean outgoing frame size at least 700 bytes. | 76 | Large DNS responses or internal DNS tools |

Edit values in `config/anomaly.toml`; `scripts/evaluate_anomaly.py` reports how a change behaves against the bundled synthetic fixtures. Rule thresholds are not universal security boundaries. The port-scan rules use the source endpoint seen first in the capture, which may be the responder if a capture starts mid-flow.

## Statistical score and explanations

The Isolation Forest is fitted only on features extracted from `sample_data/normal.pcap`. Its 1st percentile score threshold and per-feature means/standard deviations are stored in `models/anomaly_metadata.json`. Statistical explanations include the strongest feature deviations above the configured z-score cutoff, currently 3 standard deviations. Rule explanations are plain language, such as the observed upload/download ratio or packet rate.

The model score contributes at most 40 points. The highest rule score is combined with that model component and capped at 100. Severity bands are:

- Low: 0–29
- Medium: 30–59
- High: 60–100

Alerts are triage signals. They do not establish intent, identify an application, or automatically block traffic.
