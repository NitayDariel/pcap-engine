# PCAP Threat Analysis Engine

Automated PCAP forensics pipeline. Feed it a capture file, get a threat report with MITRE ATT&CK findings, IOC extraction, Wireshark filters, and artifact analysis — in under 10 seconds.

---

## What it does

1. **Orients** — builds host inventory, protocol map, visibility metrics (Phase 1)
2. **Signals** — parses Zeek logs into 40+ pre-aggregated fields: DNS entropy, Kerberos TGS, DRSUAPI, scan states, beacon intervals (Phase 2)
3. **Beacon detection** — RITA-style 4-factor composite scoring with FFT for jitter-masked C2 (Phase 2)
4. **Signature scan** — Suricata with ET Open rules; maps SID → MITRE technique (Phase 2.5, optional)
5. **TTP sweep** — scores 21 YAML playbooks in parallel; tiered thresholds reduce cliff-edge FP (Phase 3)
6. **Deep dive** — targeted tshark evidence for high-scoring findings (Phase 4)
7. **Artifacts** — SHA256-hashes extracted files, analyzes TLS certs, surfaces SMB write events (Phase 5)
8. **IOC enrichment** — VirusTotal + ThreatFox lookups per external IP (Phase 6)
9. **Anomaly layer** — flags uncategorised patterns outside playbook coverage (Phase 7)
10. **Outputs** — `report.md`, `findings.json`, `anomalies.json`, `wireshark_filters.md`

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
suricata   # brew install suricata  → ET Open signature detection
docker     # + Colima               → RITA gold-standard beacon scoring
zkg        # zeek package manager   → JA3 TLS fingerprinting
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
  report.md              # full threat report
  findings.json          # structured TTP results
  anomalies.json         # uncategorised patterns
  wireshark_filters.md   # ready-to-paste display filters with real IPs
```

---

## Architecture

```
pcap-engine/
├── engine/
│   ├── main.py                  # pipeline entry point
│   ├── phase1_orientation.py    # AnalysisContext: host inventory, protocols
│   ├── phase2_protocol.py       # ProtocolSignals: 40+ pre-aggregated fields
│   ├── phase2_beacon.py         # RITA 4-factor beacon scoring + FFT
│   ├── phase3_ttp_sweep.py      # parallel YAML playbook scorer
│   ├── phase4_deep_dive.py      # tshark deep-dive evidence
│   ├── phase5_artifacts.py      # files, TLS certs, SMB events
│   ├── phase6_ioc_enrichment.py # VT + ThreatFox
│   ├── phase7_anomaly.py        # uncategorised pattern detection
│   ├── scorer.py                # tiered threshold evaluation engine
│   ├── reporter.py              # markdown report generator
│   ├── wireshark_export.py      # display filter generator
│   └── utils/
│       ├── zeek.py              # Zeek runner + log parsers
│       ├── tshark.py            # tshark wrappers
│       ├── suricata.py          # Suricata offline scanner
│       ├── vt_client.py         # VirusTotal API
│       └── abusech_client.py    # ThreatFox API
├── playbooks/                   # 21 YAML detection playbooks
│   ├── c2_and_beaconing/
│   ├── credential_access/
│   ├── discovery/
│   ├── exfiltration/
│   ├── lateral_movement/
│   └── reconnaissance/
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
    threshold_low: ">= 30"             # tiered: partial credit
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

**Signal sources** are field names on `ProtocolSignals` — the API contract between Phase 2 and playbooks. Adding a new detection means: (1) add a field to `ProtocolSignals`, (2) compute it in `phase2_protocol.py`, (3) reference it in a YAML `source:` key.

---

## Adding a Playbook

1. Create `playbooks/<category>/T<id>_<name>.yaml`
2. Define signals referencing existing `ProtocolSignals` fields
3. Or: add a new field to `ProtocolSignals` + compute it in `phase2_protocol.py`
4. Run engine — playbook is auto-loaded from the directory

No code changes needed for playbook-only additions.

---

## Environment Variables

For live IOC enrichment (Phase 6), set in `.env`:

```
VT_API_KEY=your_virustotal_key
THREATFOX_API_KEY=your_threatfox_key  # optional, public API available
```

---

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for:
- Implementation status per phase
- Verification matrix (PCAP results vs answer PDFs)
- Planned sprints (JA3, Sigma, RITA, 9 more playbooks)
- Known gaps

**Status**: implemented and smoke-tested. Formal verification against answer PDFs is the current priority before any new features.
