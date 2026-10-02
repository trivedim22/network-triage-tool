# Network Traffic Triage Tool

Beginner-friendly, browser-based cybersecurity education project. Capture traffic in Wireshark, export the packet list as CSV, upload it here, and get an easy-to-understand triage report that teaches how a SOC analyst spots activity **worth investigating**.

> Educational network triage tool. Alerts indicate activity worth investigating and do not prove malicious behaviour.
> Only analyse traffic from systems and networks you own or are authorised to monitor.

**Privacy:** Your packet capture data is analysed locally in your browser and is not uploaded anywhere. No server, no AI API, no analytics, tracking, cookies, ads, or telemetry.

## What it does

1. You capture in Wireshark and export **File > Export Packet Dissections > As CSV**.
2. You upload the CSV (drag-and-drop supported) or load a demo sample.
3. The app parses the CSV **locally**, shows file status (filename, packet count, parse success, missing fields).
4. You get a dashboard: totals, unique hosts, most active hosts, top 10 sources/destinations, protocol distribution, explainable investigation score.
5. Rule-based alerts (no ML) explain *why* something deserves a look, with benign explanations and investigation steps.
6. Filters + configurable thresholds + "How to Think Like an Analyst" lessons.

## How to run locally on Windows

No installation needed. Nothing to install — no Node, no Python, no packages.

Option A — double-click:
1. Open the `network triage tool` folder.
2. Double-click `index.html`. It opens in Edge/Chrome/Firefox.

Option B — local server (only needed if the "Load Sample" buttons are blocked by `file://` rules in your browser):
```powershell
# in the project folder
python -m http.server 8000
# then open http://localhost:8000
```
If samples fail to load with `file://`, use the file picker instead — that always works.

To host as a static site later: upload `index.html`, `styles.css`, `script.js`, and the `samples/` folder to any static host (GitHub Pages, Netlify, S3 static, etc.). No build step.

## How to export Wireshark packets as CSV

1. Open Wireshark.
2. Capture traffic in an authorised environment.
3. Stop the capture.
4. **File > Export Packet Dissections > As CSV**.
5. Save and upload into this tool.

Only capture traffic from systems and networks you own or are authorised to monitor.

## Supported CSV fields (tolerant parser)

Expected headers (case/spacing tolerant): `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.

Aliases accepted (after lowercasing + stripping non-alphanumerics):
- Source: `source`, `source ip` → `sourceip`, `src`, `ip.src` → `ipsrc`, `source address`, etc.
- Destination: `destination`, `dst`, `dest`, `ip.dst` → `ipdst`, etc.
- Protocol: `protocol`, `proto`
- Length: `length`, `len`, `bytes`, `size`, `frame len`
- Info: `info`, `information`, `details`, `summary`
- Time: `time`, `timestamp`, `arrival time`

If required fields are missing the app does not crash — it shows e.g. "This CSV does not appear to contain a Source address column." Port-scan and SYN rules are skipped gracefully when the `Info` column lacks port/flag detail.

## Detection rules (all explainable, no ML)

| # | Rule | Default | Severity | What it shows |
|---|------|---------|----------|---------------|
| 1 | High packet volume (per source) | > 50 | Medium (High if > 3×) | source, count, threshold, why + benign causes + steps |
| 2 | Possible host scanning (unique destinations per source) | > 10 | Medium | source, unique-dest count |
| 3 | Possible port scanning (unique dst ports on one dst, from Info) | > 10 | Medium | source, dst, ports sampled |
| 4 | High ICMP activity (per source) | > 30 | Low/Medium | troubleshooting vs ping sweep vs DoS discussion |
| 5 | High DNS activity (per source) | > 30 | Low | browsing/updates vs beaconing discussion |
| 6 | Repeated src→dst communication | > 40 | Informational | pair, count, top protocol |
| 7 | Repeated TCP SYN activity (Info contains SYN) | > 20 | Medium/High | never called a "SYN flood" — needs Wireshark follow-up |

Every alert contains: name, severity (Informational/Low/Medium/High — priority, not certainty), source/dst, observed activity, configured threshold, why it could matter, benign explanations, suggested investigation.

**Investigation score (explainable, not a probability):** +20 high volume, +15 many destinations, +15 high ICMP, +10 high DNS, +10 many ports, +10 repeated pair, +10 SYN. Label: Quiet / Minor / Notable / Elevated / High. Breakdown is always listed. Never a fake "97% malicious" score.

### Why thresholds are not universal

Thresholds should be adjusted based on the environment. A busy server may legitimately generate thousands of packets, while the same activity from another endpoint might deserve investigation. Use Settings → Re-analyse, and Reset Defaults anytime.

## Sample data (`samples/`)

All fictional, private/reserved IPs only (`192.168.x.x`, `10.x.x.x`), no real malicious infrastructure.

- `normal-traffic.csv` (34 pkts) — ordinary DNS/TCP/ARP. Expect: 0 alerts.
- `high-volume-traffic.csv` (80 pkts) — one source `192.168.1.25` with 70 packets to `10.0.0.5`. Expect: High activity host + Repeated pair.
- `mixed-soc-lab.csv` (~263 pkts) — high-volume + 26-destination scan + 13-port + 12-port scans + 35 ICMP + 35 DNS + repeated pairs + SYN burst. Expect: all rule families fire — ideal for the 4-part video demo.

In-app buttons: Load Normal Sample / Load Suspicious Sample / Load Mixed SOC Lab (labelled "Demo Data").

Video demo path: Normal → quiet → Suspicious → High Packet Volume → Mixed → Scanning + ICMP → close with: "Detection tells an analyst where to look. Investigation determines what actually happened."

## Limitations (read before demoing)

- CSV has far less than a PCAP (no full headers, payloads, precise flags, timing analysis).
- Encrypted traffic limits visibility (TLS/HTTPS contents unseen).
- Volume alone never proves malice; NAT skews attribution; Wireshark protocol labels are interpretive.
- No malware analysis; not a replacement for Wireshark, IDS, SIEM, or professional monitoring.
- Thresholds are educational defaults; tune per environment.
- Time-window/burst detection not in V1 (counts are per-capture).

## False positives to expect

Backups, updates, streaming, monitoring tools, authorised scanners, admin troubleshooting, chatty apps, and reconnect loops all trigger these rules legitimately. That is the lesson: an anomaly is a starting point for investigation, not proof of compromise.

## Privacy & security design

- 100% client-side HTML/CSS/vanilla JS. No backend, DB, cloud, AI API, keys, frameworks, or dependencies.
- FileReader + `fetch()` only for local `samples/`. No external requests.
- File type/size checks; malformed CSV fails with a message, never crashes.
- CSV treated as untrusted: DOM built with `textContent`/`createElement`; `innerHTML` used only as `=""` to clear containers; nothing from the CSV is executed or sent anywhere.
- Verified: normal → 0 alerts; high-volume → Rule 1 fires; mixed → Rules 1/2/4/5/6 (+3 port-scan, +7 SYN) fire; malformed/empty CSV shows safe error; `node --check script.js` passes.

## Future improvements (not in V1)

Direct `.pcap`/`.pcapng`, TCP flag analysis, time-window detections, baselining, network graphs, GeoIP, threat-intel enrichment, DNS-domain analysis, exportable SOC report, IDS-style rules. No external APIs in V1 by design.

## Educational use

"How to Think Like an Analyst": Observe → Identify src/dst → Determine protocol → Establish if expected → Look for supporting indicators → Correlate telemetry → Decide next step. Central lesson: **An anomaly is a starting point for investigation, not proof of compromise.**
