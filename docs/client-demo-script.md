# 75-second client demo script

Use a sanitized capture you are allowed to share. For a public recording, use a sample capture with no client addresses, DNS names, or private session details. The dashboard does not display endpoints, but the capture itself can still contain sensitive information.

| Time | On screen | Voiceover |
| --- | --- | --- |
| 0–10 sec | Open the upload demo. Pause on the headline and payload note. | “Most network traffic is encrypted, but packet sizes and timing still reveal useful patterns. This demo estimates what a flow resembles without decrypting its contents.” |
| 10–20 sec | Click **With injected attacks** (or choose a sanitized `.pcap` you may share) and select **Analyze capture**. | “I’ll load a packet capture. The parser reads packet lengths, timing, direction, and only the transport headers it needs.” |
| 20–35 sec | Show the flow and packet totals, then the traffic-mix bar. | “The capture is grouped into bidirectional flows. Lead with the anomaly view: the injected scans and bursts are flagged with plain-language reasons. If the traffic-mix panel shows a low-confidence warning, say so; the bundled sample is synthetic, so the class mix is not meaningful.” |
| 35–48 sec | Scroll through the largest-flow table and a low-confidence row if present. | “Each row gives the predicted class and model confidence. Low-confidence flows stay uncertain; the result does not name an app or website.” |
| 48–63 sec | Scroll to the validation note and confusion matrix in the README. | “This is an early model. Its current held-out accuracy is about 63 percent, and the data split is by flow rather than capture session, so the score may be optimistic.” |
| 63–75 sec | Return to the privacy note and end on the project title. | “The goal is privacy-aware network visibility. For private traffic, run the demo locally; a hosted copy receives uploaded files on its server.” |

Record the browser and narration together, then export a 60–90 second MP4 or a short GIF without including a sensitive capture filename. Link it near the top of the GitHub README and in the project portfolio entry.
