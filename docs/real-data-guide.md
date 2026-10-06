# Real data, real numbers, and getting it online

Four jobs, in order. Each one ends with a number or a link you can put in the README.

## 1. Public datasets you can use

| Dataset | What it gives you | Use it for |
| --- | --- | --- |
| **ISCXVPN2016** (UNB Canadian Institute for Cybersecurity) | Labeled packet captures (pcap) plus flow CSVs. Apps such as Netflix, YouTube, Vimeo, Spotify, Skype, Hangouts, FTPS/SFTP/SCP, email and torrents, each also captured over a VPN. No gaming. | Classifier: streaming, video call, download, browsing |
| **CIC-IDS2017** (same institute) | Five days of pcaps. Monday is benign only; later days contain attacks (the published list includes port scan, DoS/DDoS, brute force, botnet). The dataset page documents attack times and machines. | Anomaly detector: attack recall and false-alarm rate |
| **CTU-13** (Stratosphere Lab, CC-BY) | 13 captures with botnet, normal and background traffic | A second, different anomaly check |
| **UNSW-NB15** | Raw pcaps plus labeled flow CSVs | Another anomaly check |
| **MAWI Samplepoint-F, Netresec index, Wireshark sample captures** | Unlabeled or lightly labeled captures (MAWI is headers only) | Extra benign traffic to measure false alarms |

Notes:
- Get each dataset from its official page; search for its name. An unofficial Hugging Face mirror of CIC-IDS2017 exists, but check the terms before using it.
- Some pcap archives (Netresec's malware sections, malware-traffic-analysis.net) contain real malware. Download captures only, never run anything from them, and use a lab VM if you are unsure.
- Files are big (a single CIC-IDS2017 day is several GB). The scripts below stream them and never load a whole file.
- **Licenses.** ISCXVPN2016 and CIC-IDS2017 are published for researchers and ask for citation. If you plan to sell services, do not put their files in your repository or in a client deliverable, cite them in the README, and prefer your own captures for anything shown to clients. CTU-13 is CC-BY: credit it.
- **Gaming is missing** from ISCXVPN2016. Record 3-5 sessions of a free online game yourself (steps in section 5), or drop the class and train with four.

## 2. Whole-session accuracy (your step 1)

```powershell
# a. Preview how the downloaded files map to your five classes (nothing is written)
python scripts/prepare_public_captures.py C:\data\ISCX captures --dry-run

# b. Trim each file to 100,000 packets and sort into captures\<label>\
python scripts/prepare_public_captures.py C:\data\ISCX captures

# c. Add your own recordings to the same folders, then build the dataset
python scripts/build_dataset_from_pcaps.py captures --append

# d. Train. Each file is one session, so whole sessions are held out
python src/train.py
```

Check these before you trust the result:
- The dry run lists files it could not match. Edit `RULES` at the top of `scripts/prepare_public_captures.py` if your copy names them differently.
- Aim for at least 4 sessions per class. The dataset script warns if a class has fewer.
- Read `reports/evaluation.md`. It states the session-held-out accuracy and confusion matrix. Copy those numbers into the README, even if they are lower than 62.7%.
- Say in the README where the data came from (your captures, ISCXVPN2016) and that the model was tested on held-out sessions, not held-out flows.
- 2016 apps and 2026 apps look different on the wire. Report the score as "on this data" and do not claim it will hold on a client's network.

## 3. Test the anomaly detector on traffic you did not generate (your step 2)

```powershell
# Attack recall: pull the attacker's packets out of an attack-day capture.
# Find the attacker IP and the attack window in the dataset's documentation.
python scripts/slice_pcap.py C:\data\Friday-WorkingHours.pcap slices\attack.pcap --host ATTACKER_IP --packets 100000
python scripts/evaluate_external.py slices\attack.pcap --attacker-ip ATTACKER_IP --output reports\external_attack.md

# False alarms: a day or capture with no attacks (Monday in CIC-IDS2017)
python scripts/slice_pcap.py C:\data\Monday-WorkingHours.pcap slices\benign.pcap --packets 100000
python scripts\evaluate_external.py slices\benign.pcap --output reports\external_benign.md
```

- The attack slice only contains the attacker's own packets, so it measures **recall**. The benign slice measures the **false-alarm rate**. Report both.
- Pulling a slice by host keeps only part of each conversation, which can make flows look different from real traffic. If the numbers look odd, slice by time instead (`--start` and `--end`, Unix timestamps) and pass the attacker IP to the evaluator.
- Put the real results in the README next to the synthetic ones, and mark the synthetic ones as self-generated. Low recall on a real attack is a finding, not a failure: it tells you what to improve.

## 4. Live link and your name on the LICENSE (your step 3)

**License.** Open `LICENSE`, and change line 3 to your own name:

    Copyright (c) 2026 Your Full Name

**GitHub.**

```powershell
git init
git add .
git commit -m "Signal / Flow: encrypted traffic monitor"
git branch -M main
git remote add origin https://github.com/YOUR-USER/signal-flow.git
git push -u origin main
```

Create the empty `signal-flow` repository on github.com first. `.gitignore` already keeps `captures/`, virtual environments and build files out.

**Render.**
1. render.com: New, then Blueprint, then connect the GitHub repo.
2. Render reads `render.yaml` (free plan, health check at `/healthz`, secret key generated for you). Click Apply.
3. When the deploy finishes, open the `.onrender.com` link and click **With injected attacks**.
4. Paste the link at the top of the README, your GitHub profile and your gig.
- The free plan sleeps when idle and takes up to a minute to wake. Open the link yourself shortly before showing it to a client.
- The hosted demo is public. Never upload a client's capture to it. See section 6.

## 5. Recording your own sessions (also fills the gaming gap)

Use Wireshark or `dumpcap`, and do one activity per recording, 2-4 minutes each, with nothing else running:

| Folder | What to do while recording |
| --- | --- |
| `captures/browsing/` | Browse several normal websites |
| `captures/streaming/` | Play a video on a streaming site |
| `captures/video_call/` | Run a video call |
| `captures/download/` | Download a large file |
| `captures/gaming/` | Play a free online game |

Save each as its own file, such as `streaming/yt-1.pcap`, `streaming/yt-2.pcap`, on different days if you can. More sessions help more than longer ones. Only packet sizes, directions, ports and timing are used; payloads never are.

## 6. Selling the work (your step 4)

Sell the analysis, not the zip. Typical offers:
- **Capture review:** you analyze one capture a client sends and deliver a short report (template: `docs/client-report-template.md`).
- **Setup and customization:** install the dashboard on the client's machine and adapt it to their traffic.
- **Evaluation on their data:** run sections 2 and 3 on their captures and report honest accuracy.

Rules that protect you and the client:
- Client captures contain sensitive information. Run the analysis on your machine or theirs, never on the public Render demo, and delete the files when the job ends. Say this in writing before you start.
- Get written permission before touching anyone's network or traffic, and capture only networks you are authorized to monitor.
- Say what the tool cannot do: it estimates traffic types from metadata and flags unusual patterns. It does not identify applications, confirm compromise, or replace a security team.
- Quote prices after seeing the size of the capture and the work. Check your college's rules on selling work built during coursework.
