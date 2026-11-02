# Ablation: rules versus learned model

- Capture: `my_browsing.pcap` (100,000 packets read, 65 flows)
- Ground truth: flows touching no attacker IP (benign-only run)
- Attack flows / benign flows: 0 / 65
- Alert = medium or high severity under each variant.

| Variant | Recall | False-alarm rate | TP / FP / FN / TN |
| --- | ---: | ---: | ---: |
| Rules only | n/a (no attack flows) | 0.0% | 0 / 0 / 0 / 65 |
| Model only | n/a (no attack flows) | 0.0% | 0 / 0 / 0 / 65 |
| Both (dashboard) | n/a (no attack flows) | 0.0% | 0 / 0 / 0 / 65 |

- Attack flows alerted only because of the model: 0
- Benign flows alerted only because of the model: 0

How to read it: if "both" is no better than "rules only" on attack traffic, the learned model adds nothing there. If it adds attack flows, compare that gain with the benign flows it also adds. One capture, IP-derived labels; not a benchmark.
