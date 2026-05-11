# PCAP Threat Analysis Engine

Automated PCAP forensics pipeline. Feed it a capture file, get a structured threat report with MITRE ATT&CK findings, IOC extraction, JA3 fingerprint hits, Wireshark filters, and artifact hashes — in under 15 seconds.

---

## The Problem

Triaging a suspicious PCAP manually means:

- Running Zeek, parsing 10+ log files by hand
- Correlating DNS anomalies, TLS cert issues, and beaconing intervals across separate tools
- Writing Wireshark filters from scratch for every artifact of interest
- Looking up every external IP in VirusTotal one-by-one
- Missing C2 that blends into normal traffic because there's no baseline engine

A mid-complexity infection capture takes 30–90 minutes this way. A novel malware family takes longer because you don't know what to look for.

This engine makes that 15 seconds.

---

## What It Detects

The engine runs **four independent detection layers** over every PCAP:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                        DETECTION LAYERS                                        │
├──────────────────────────┬───────────────────────────────────────────────────┤
│  Layer                   │  What It Covers                                   │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  Behavioral (Playbooks)  │  30 MITRE ATT&CK TTPs — protocol anomalies,       │
│                          │  Kerberos attacks, scan patterns, exfil signals    │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  Signatures (Suricata)   │  Emerging Threats Open rules — malware family      │
│                          │  identification, known C2 infrastructure           │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  Beacon Scoring (RITA)   │  4-factor composite: jitter, skew, top-connected,  │
│                          │  connections/hour + FFT for masked beacon intervals │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  TLS Fingerprinting      │  JA3/JA3S hashes matched against known-bad list:   │
│  (JA3)                   │  Cobalt Strike, Meterpreter, common RAT clients    │
└──────────────────────────┴───────────────────────────────────────────────────┘
```

Results from all four layers are combined. Suricata signature hits boost TTP scores (+0.10, HIGH confidence) where a confirmed signature matches the same technique.

---

## Detection Coverage Matrix

The 30 playbooks cover 6 MITRE ATT&CK tactic areas. Each row shows which detection tools contribute:

```
┌───────────────────────────────┬──────────┬──────────┬───────────┬─────────────────────┐
│  MITRE Tactic                 │ Playbook │ Suricata │ Beacon    │ IOC Enrichment       │
│                               │  TTPs    │  Sigs    │ Scoring   │ VT · ThreatFox       │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  C2 & Beaconing  (TA0011)     │  11 ✓    │    ✓     │    ✓      │  ✓ IP + Domain       │
│  T1071  Generic C2 Beaconing  │          │    ✓     │    ✓      │                      │
│  T1071.001  HTTP C2           │          │    ✓     │    ✓      │                      │
│  T1071.004  DNS Tunneling     │          │    ✓     │           │                      │
│  T1095  ICMP C2               │          │          │           │                      │
│  T1102  Web Service C2        │          │    ✓     │           │                      │
│  T1132.001  Base64 Encoding   │          │          │           │                      │
│  T1008  Fallback Channels     │          │    ✓     │    ✓      │                      │
│  T1036.005  Masquerading      │          │    ✓     │           │                      │
│  T1219  RAT C2                │          │    ✓     │    ✓      │  ✓ JA3               │
│  T1572  Protocol Tunneling    │          │    ✓     │           │                      │
│  T1573.001  TLS C2            │          │    ✓     │    ✓      │  ✓ JA3               │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Credential Access  (TA0006)  │   5 ✓    │    ✓     │           │                      │
│  T1003.006  DCSync            │          │    ✓     │           │                      │
│  T1040  Credential Sniffing   │          │          │           │                      │
│  T1056.003  Web Portal Capture│          │          │           │                      │
│  T1110.001  Kerberos Bruteforce│         │    ✓     │           │                      │
│  T1558.003  Kerberoasting     │          │    ✓     │           │                      │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Discovery  (TA0007)          │   4 ✓    │    ✓     │           │                      │
│  T1016  Network Config        │          │          │           │                      │
│  T1018  Remote System         │          │    ✓     │           │                      │
│  T1049  Network Connections   │          │    ✓     │           │                      │
│  T1135  Network Share         │          │    ✓     │           │                      │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Lateral Movement  (TA0008)   │   5 ✓    │    ✓     │           │  ✓ IP                │
│  T1021.001  RDP               │          │    ✓     │           │                      │
│  T1021.002  SMB/PsExec        │          │    ✓     │           │                      │
│  T1021.006  WinRM             │          │    ✓     │           │                      │
│  T1550.002  Pass-the-Hash     │          │    ✓     │           │                      │
│  T1557  ARP MitM              │          │          │           │                      │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Exfiltration  (TA0010)       │   3 ✓    │    ✓     │    ✓      │  ✓ IP + Domain       │
│  T1041  Exfil via C2          │          │    ✓     │    ✓      │                      │
│  T1048.001  DNS TXT Exfil     │          │    ✓     │           │                      │
│  T1048.003  Unencrypted Exfil │          │    ✓     │           │                      │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Reconnaissance  (TA0043)     │   2 ✓    │    ✓     │           │  ✓ IP                │
│  T1046  Port Scan             │          │    ✓     │           │                      │
│  T1595  Active Scanning       │          │    ✓     │           │                      │
├───────────────────────────────┼──────────┼──────────┼───────────┼─────────────────────┤
│  Anomaly Layer (catch-all)    │    —     │    —     │    —      │  AI analysis         │
│  Uncategorised patterns that  │          │          │           │  Flags anything not  │
│  don't fit any playbook       │          │          │           │  covered above       │
└───────────────────────────────┴──────────┴──────────┴───────────┴─────────────────────┘
```

---

## What Each Tool Answers

```
QUESTION                              ANSWERED BY
─────────────────────────────────────────────────────────────────────────────────
Is this traffic beaconing to C2?      Beacon Scoring (RITA 4-factor + FFT jitter)
What malware family is this?          Suricata ET Open rules + JA3 fingerprints
Which ATT&CK techniques are in use?   30 YAML playbooks (behavioral signals)
Are the external IPs known-bad?       VirusTotal + ThreatFox (Phase 6)
Are the C2 domains known-bad?         Suricata domain extraction + VirusTotal
What files were transferred?          Phase 5 artifact extraction + SHA256 hash
Is the TLS suspicious?                JA3 fingerprint + cert anomaly analysis
Who is the victim?                    Zeek DHCP + Kerberos + mDNS + SMB join
What happened on this machine?        Wireshark filters + deep-dive tshark evidence
What if nothing matched?              Anomaly layer → structured anomaly report
```

---

## The Anomaly Layer

Not every attack is in a playbook. The anomaly layer runs **after** all TTP scoring and captures patterns that don't fit any known technique:

- High volume of connections to a single external IP (below the C2 beaconing threshold)
- Protocol behavior that's statistically unusual for the capture (e.g. rare DNS record types)
- Sessions without any corroborating signals (no Suricata, no playbook, just weird)

These are written to `anomalies.json` alongside the report. An analyst (or AI) can review them against the TTP findings and make a determination. This two-stage approach — score first, flag the rest — keeps the false positive rate low while ensuring nothing is silently discarded.

---

## IOC Enrichment Details

```
IOC Source                          Enriched By
──────────────────────────────────────────────────────
External IPs (top talkers)          VirusTotal (detections + reputation)
                                    ThreatFox (malware family, confidence %)
IPs from TTP findings               VirusTotal + ThreatFox (prioritised)
IPs with self-signed TLS certs      Added to IOC list (via x509.log join)
HTTP POST destinations              VirusTotal + ThreatFox
Domains from Suricata alerts        Extracted from ET rule text (regex)
Domains with >10 unique FQDNs       DNS diversity gate (tunneling indicator)
File hashes (HTTP/SMB streams)      SHA256 via tshark export
TLS fingerprints (JA3)              Matched offline against known-bad list
```

Rate limited to 4 VirusTotal requests/minute (free tier). Max 20 IPs per run.

---

## Pipeline

```
┌──────────┐
│  PCAP    │
└────┬─────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 1 — Orientation                                         │
│  Host inventory · Protocol map · Internal/external IPs         │
│  Visibility % · Top talkers · Capture window                   │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 2 — Protocol Signals + Beacon Scoring                   │
│  Zeek logs → 80+ pre-aggregated fields (ProtocolSignals)       │
│  DNS entropy · Kerberos TGS · DRSUAPI · Scan states           │
│  Beacon: RITA 4-factor composite + FFT jitter detection        │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 2.5 — Suricata (optional)                               │
│  ET Open rules · Maps SID → MITRE technique                    │
│  Alert confidence boosts Phase 3 scores (+0.10 HIGH)           │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 3 — TTP Sweep (parallel)                                │
│  30 YAML playbooks · Tiered threshold scoring                  │
│  score ≥ 0.60 → deep dive · score ≥ 0.35 → reported           │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 4 — Deep Dive                                           │
│  tshark targeted evidence for high-score TTPs                  │
│  Connection details · Packet samples · Protocol breakdown      │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 5 — Artifact Extraction                                 │
│  Files: SHA256 hash all HTTP/SMB streams                       │
│  TLS: cert analysis (self-signed, expired, generic CN)         │
│  SMB: file write events (lateral movement evidence)            │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 6 — IOC Enrichment                                      │
│  VirusTotal + ThreatFox per external IP                        │
│  JA3/JA3S fingerprint match (offline, always runs)            │
│  Suricata domain extraction from alert signatures              │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Phase 7 — Anomaly Layer                                       │
│  Flags uncategorised patterns outside playbook coverage        │
│  Output: anomalies.json (analyst/AI review)                    │
└────┬───────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────────────┐
│  Report                                                        │
│  report.md · findings.json · anomalies.json                    │
│  wireshark_filters.md (with real IPs from the capture)        │
└────────────────────────────────────────────────────────────────┘
```

---

## Requirements

**Required**
```
tshark     # brew install wireshark
zeek       # brew install zeek
python3    # 3.9+
```

**Python packages**
```bash
pip install -r requirements.txt
# key deps: pandas numpy scipy pyyaml python-dotenv requests
```

**Optional (adds detection layers)**
```
suricata   # brew install suricata       → ET Open signature detection
zkg        # zeek package manager        → JA3/JA3S TLS fingerprinting
docker     # + Colima                    → RITA gold-standard beacon scoring
```

**Installing JA3 fingerprinting**
```bash
# Fix zkg Python dependency (requires 3.10+)
pip3.14 install --break-system-packages GitPython semantic-version

# Install JA3 package (adds ja3/ja3s fields to Zeek ssl.log)
echo Y | python3.14 /opt/homebrew/bin/zkg install zeek/salesforce/ja3
```

---

## Usage

```bash
# Basic run
python engine/main.py --pcap capture.pcap

# With all options
python engine/main.py \
  --pcap capture.pcap \
  --output-dir ./outputs/my_analysis \
  --offline \                    # skip VT/ThreatFox API calls
  --max-iocs 10 \               # how many IPs to enrich
  --zeek-logs ./existing_logs \ # skip re-running Zeek
  --no-ai \                     # skip anomaly layer
  --no-suricata                 # skip Suricata scan
```

**Output**
```
outputs/<pcap_name>/
  report.md              # full threat report (victim, TTPs, IOCs, artifacts)
  findings.json          # structured TTP results
  anomalies.json         # uncategorised patterns
  wireshark_filters.md   # ready-to-paste display filters with real IPs
```

---

## Sample Output (2026-01-31 — Lumma Stealer)

```
Victim:  10.1.21.58 · DESKTOP-ES9F3ML · gwyatt · win11office.com

Top Findings:
  [HIGH    ] T1046   Network Port Scan              score=1.000
  [MEDIUM  ] T1135   Network Share Discovery        score=0.900
  [HIGH    ] T1573.001  TLS C2 (Invalid Certs)      score=0.850
  [MEDIUM  ] T1003.006  DCSync                      score=1.000

IOC Domains:
  whitepepper.su   ← Lumma Stealer C2 (from Suricata ET rule)
  whooptm.cyou     ← Lumma Stealer related

IOC IPs:
  153.92.1.49      ← Lumma Stealer C2 (VT: 2 malicious engines)
  80.97.160.24     ← MALICIOUS (VT: 5 engines)
```

---

## Environment Variables

For live IOC enrichment, set in `.env`:

```
VT_API_KEY=your_virustotal_key
THREATFOX_API_KEY=your_threatfox_key  # optional — public API works without key
```

---

## Architecture

```
pcap-engine/
├── engine/
│   ├── main.py                  # pipeline entry point
│   ├── phase1_orientation.py    # AnalysisContext: host inventory, protocols
│   ├── phase2_protocol.py       # ProtocolSignals: 80+ pre-aggregated fields
│   ├── phase2_beacon.py         # RITA 4-factor beacon scoring + FFT
│   ├── phase3_ttp_sweep.py      # parallel YAML playbook scorer
│   ├── phase4_deep_dive.py      # tshark deep-dive evidence
│   ├── phase5_artifacts.py      # files, TLS certs, SMB events
│   ├── phase6_ioc_enrichment.py # VT + ThreatFox + JA3 fingerprint check
│   ├── phase7_anomaly.py        # uncategorised pattern detection
│   ├── scorer.py                # tiered threshold evaluation engine
│   ├── reporter.py              # markdown report generator
│   ├── wireshark_export.py      # display filter generator
│   └── utils/
│       ├── zeek.py              # Zeek runner + log parsers (loads JA3 package)
│       ├── tshark.py            # tshark wrappers
│       ├── suricata.py          # Suricata offline scanner
│       ├── vt_client.py         # VirusTotal API
│       └── abusech_client.py    # ThreatFox API
├── playbooks/                   # 30 YAML detection playbooks
│   ├── c2_and_beaconing/        # 11 TTPs: T1071, T1095, T1219, T1572...
│   ├── credential_access/       # 5 TTPs: DCSync, Kerberoasting, sniffing...
│   ├── discovery/               # 4 TTPs: port scan, share enum, net config...
│   ├── exfiltration/            # 3 TTPs: DNS exfil, C2 channel, cleartext...
│   ├── lateral_movement/        # 5 TTPs: RDP, SMB, WinRM, PTH, ARP MitM...
│   └── reconnaissance/          # 2 TTPs: port scan, active scanning...
└── ROADMAP.md                   # what's done, what's next, verification status
```

---

## Playbook Format

Each playbook is a YAML file defining a MITRE ATT&CK technique detection:

```yaml
ttp_id: T1046
name: Network Port Scan
category: reconnaissance
required_protocols: [tcp]

minimum_presence:
  scan_candidate_count: 0   # gate: skip if protocol absent

signals:
  - id: high_unique_ports
    source: scan_max_unique_dst_ports   # field name in ProtocolSignals
    threshold: ">= 100"
    weight: 0.55
    threshold_low: ">= 30"             # tiered: partial credit below main threshold
    weight_low: 0.25
    attack_category: A

combination_bonuses:
  - signals: [high_unique_ports, syn_only_connections]
    bonus: 0.15
    reason: Multi-port + SYN-only = confirmed scanner

score_thresholds:
  deep_dive: 0.60
  report: 0.35
```

**Signal sources** are field names on `ProtocolSignals` — the API contract between Phase 2 and playbooks. Adding a new detection: (1) add field to `ProtocolSignals`, (2) compute in `phase2_protocol.py`, (3) reference in a YAML `source:` key.

---

## Verification

Tested against 5 real-world malware exercise PCAPs with published ground-truth answers:

| PCAP | Malware | Victim | C2 IPs | Key Techniques |
|---|---|---|---|---|
| 2024-09-04 | Koi Stealer | ✅ afletcher · 172.17.0.99 | ✅ 79.124.78.197 | T1219 HIGH |
| 2024-11-26 | NetSupport RAT | ✅ oboomwald · 10.11.26.183 | ✅ 194.180.191.64 | T1219 HIGH |
| 2025-01-22 | Fake Teams malware | ✅ shutchenson · 10.1.17.215 | ✅ 3/3 C2 IPs | T1573.001 HIGH |
| 2026-01-31 | Lumma Stealer | ✅ gwyatt · 10.1.21.58 | ✅ 153.92.1.49 | T1046/T1049 + Domains |
| 2026-02-28 | NetSupport RAT | ✅ brolf · 10.2.28.88 | ✅ 45.131.214.85 | T1219 HIGH |

All 5 PCAPs: victim identification 5/5 · C2 IP coverage 11/11 · zero safe-domain leakage in IOC output.

See [`ROADMAP.md`](ROADMAP.md) for full verification matrix and sprint history.
