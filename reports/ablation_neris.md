# Ablation: rules versus learned model

- Capture: `neris.pcap` (100,000 packets read, 5,230 flows)
- Ground truth: flows touching 147.32.84.165
- Attack flows / benign flows: 5,230 / 0
- Alert = medium or high severity under each variant.

| Variant | Recall | False-alarm rate | TP / FP / FN / TN |
| --- | ---: | ---: | ---: |
| Rules only | 99.8% | n/a (no benign flows) | 5219 / 0 / 11 / 0 |
| Model only | 0.0% | n/a (no benign flows) | 0 / 0 / 5230 / 0 |
| Both (dashboard) | 99.8% | n/a (no benign flows) | 5219 / 0 / 11 / 0 |

- Attack flows alerted only because of the model: 0
- Benign flows alerted only because of the model: 0

How to read it: if "both" is no better than "rules only" on attack traffic, the learned model adds nothing there. If it adds attack flows, compare that gain with the benign flows it also adds. One capture, IP-derived labels; not a benchmark.
