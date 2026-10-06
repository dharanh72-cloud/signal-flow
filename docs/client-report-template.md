# Traffic analysis report: [CLIENT NAME]

Prepared by: [YOUR NAME]    Date: [DATE]    Capture: [FILE NAME, DURATION, PACKET COUNT]

## 1. Scope and data handling
- What was analyzed: one packet capture supplied by the client, [DATE RANGE].
- Method: packet metadata only (sizes, directions, ports, timing). Payload content was not read or decrypted.
- The capture was processed on [MY MACHINE / CLIENT MACHINE] and deleted on [DATE].

## 2. Summary (three sentences a manager can read)
[What was found, how serious it is, and the one action you recommend.]

## 3. What was in the traffic
| Traffic type (estimated) | Share of bytes | Confidence note |
| --- | ---: | --- |
| [e.g. Streaming] | [ ]% | [e.g. 70% of flows high confidence] |

Flows too short to classify: [N]. Flows marked needs review: [N].

## 4. Unusual activity
| Severity | Source | Reason from the tool | What it might mean | What to check |
| --- | --- | --- | --- | --- |
| [High] | [IP] | [e.g. contacted 26 distinct ports] | [e.g. a scan] | [e.g. is this a known scanner?] |

A high score is a signal to investigate. It does not confirm a compromise.

## 5. How reliable this is
- Classifier accuracy on held-out sessions: [X]% (data: [SOURCE]). Estimates are traffic types, not applications.
- Anomaly detector on external captures: recall [X]%, false-alarm rate [X]% (see reports/external_*.md).
- Limits for this capture: [one capture, short duration, encrypted metadata only, etc.].

## 6. Recommendations
1. [Action, owner, timing]
2. [Action, owner, timing]

## Appendix
Exported flow table: `signal-flow-export.csv`
