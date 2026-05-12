# PCAP Engine — Roadmap

> Live document. Update status fields in-place. Last updated: 2026-05-12 (Sprint 11A — singleton domain detection + README accuracy fixes + Gemini key update)

---

## Engine Status

| Component | Status | Notes |
|---|---|---|
| Phase 1 — Orientation | ✅ Implemented | Host inventory, protocol map, visibility % |
| Phase 2 — Protocol Signals | ✅ Implemented | Zeek logs, Kerberos, LDAP, DRSUAPI, scan states |
| Phase 2 — Beacon Scoring | ✅ Implemented | RITA 4-factor + FFT; verified no FP on short exercise PCAPs |
| Bug Sprint v9 — 6 Detection Fixes | ✅ Done | DNS SRV filter, mDNS hostname, HTTP POST IOC, MAC lookup, DCSync gate, T1219 playbook |
| Bug Sprint v9B — 2 More Fixes | ✅ Done | SMB FQDN domain override (authoritative over DHCP/Kerberos), Kerberoasting RC4 gate |
| Sprint 10A — 8 New Playbooks | ✅ Done | 30/30 target; 6 new signals (WinRM, inbound scan, PTR, base64, C2 service DNS) |
| Bug Sprint v10B — 5 IOC Fixes | ✅ Done | Suricata domain regex (space-TLD), safe-domain filter, cert anomaly IPs, scan IP filter, domain gate |
| Sprint 9A — JA3 Fingerprinting | ✅ Done | zkg salesforce/ja3 installed; packages keyword in Zeek cmd; check_ja3() in phase6; JA3 section in report |
| Sprint 9B — Sigma Rules | ✅ Done | pySigma evaluator; 21 SigmaHQ zeek rules; Phase 2.6; TTP boost; Sigma section in report |
| Report Quality Overhaul | ✅ Done | IOC dedup, hash dedup ×N, protocol filter, 30-playbook count, Suricata dedup, evidence formatter |
| Phase 2.5 — Suricata | ✅ Implemented | Graceful skip if not installed; ET Open rules |
| Phase 2.6 — Sigma Rules | ✅ Implemented | pySigma evaluator; graceful skip if unavailable; 21 network/zeek rules |
| Phase 3 — TTP Sweep | ✅ Implemented | Parallel YAML scoring; tiered thresholds; Suricata + Sigma boost |
| Phase 4 — Deep Dive | ✅ Implemented | Targeted tshark evidence for high-score TTPs |
| Phase 5 — Artifacts | ✅ Implemented | File hashes (tshark), TLS certs (x509.log), SMB events |
| Phase 6 — IOC Enrichment | ✅ Implemented | VirusTotal + ThreatFox; offline-safe |
| Phase 7 — Anomaly Layer | ✅ Implemented | Heuristic pattern detection + Gemini LLM hypothesis (graceful fallback if key absent/quota) |
| Gemini Integration | ✅ Implemented Sprint 11A | `utils/gemini_client.py`; google-genai SDK; `gemini-3.1-flash-lite`; GOOGLE_API_GENERAL_KEY primary; retry logic; `ai_hypothesis` in anomalies.json + report |
| Wireshark Export | ✅ Implemented | 8 sections, real IPs embedded, beacon filters |
| Report (MD) | ✅ Implemented | Exec summary, victim, IOCs, artifacts, beacon, Suricata |
| Scorer (tiered thresholds) | ✅ Implemented | threshold + threshold_low + _weak suffix + combo bonuses |

---

## Playbooks — 30 of 30 Target ✅

| Category | Playbooks | Count |
|---|---|---|
| C2 & Beaconing | T1008, T1071, T1071.001, T1071.004, T1095, T1132.001, T1219, T1036.005, T1102, T1572, T1573.001 | 11 |
| Credential Access | T1003.006, T1040, T1056.003, T1110.001, T1558.003 | 5 |
| Discovery | T1016, T1018, T1049, T1135 | 4 |
| Exfiltration | T1041, T1048.001, T1048.003 | 3 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002, T1557 | 5 |
| Reconnaissance | T1046, T1595 | 2 |
| **Total** | | **30 / 30** ✅ |

**Sprint 10A complete.** 8 new playbooks added: T1550.002, T1595, T1132.001, T1016, T1021.006, T1572, T1102, T1036.005.
6 new ProtocolSignals computed: `winrm_connection_count`, `inbound_scan_unique_src_count`, `dns_ptr_lookup_count`, `dns_base64_label_count`, `http_base64_uri_count`, `dns_c2_service_lookup_count`.

---

## Verified Against Ground Truth

### Verification Matrix

| PCAP Date | Run | Victim IP | Hostname | MAC | Windows User | Domain | C2 IP | TTP Fired | Score |
|---|---|---|---|---|---|---|---|---|---|
| **2024-09-04** | ✅ v10.1 | ✅ 172.17.0.99 | ✅ DESKTOP-RNVO9AT | ✅ | ✅ afletcher | ✅ bepositive.com | ✅ 79.124.78.197 | T1219 HIGH | **~8/10** |
| **2024-11-26** | ✅ v10.1 | ✅ 10.11.26.183 | ✅ desktop-b8tqk49 | ✅ | ✅ oboomwald | ✅ nemotodes.health | ✅ 194.180.191.64 | T1219 HIGH | **~8/10** |
| **2025-01-22** | ✅ v10.1 | ✅ 10.1.17.215 | ✅ DESKTOP-L8C5GSJ | ✅ | ✅ shutchenson | ✅ bluemoontuesday.com | ✅ 3/3 C2 IPs (cert join) | T1573.001 HIGH | **~8/10** |
| **2026-01-31** | ✅ v10.1 | ✅ 10.1.21.58 | ✅ DESKTOP-ES9F3ML | ✅ | ✅ gwyatt | ✅ win11office.com | ✅ 153.92.1.49 + domains | T1046/T1049 + Lumma IOC | **~8/10** |
| **2026-02-28** | ✅ v10.1 | ✅ 10.2.28.88 | ✅ DESKTOP-TEYQ2NR | ✅ | ✅ brolf | ✅ easyas123.tech | ✅ 45.131.214.85 | T1219 HIGH | **~8/10** |

---

### 2024-11-26 — Full Analysis (NetSupport RAT / SmartApeSG)

**Ground truth**: NetSupport RAT, delivered via SmartApeSG fake browser update (`classicgrand.com` → `modandcrackedapk.com` → `Udate.js`). C2 to `194.180.191.64:443` (HTTP POST, not HTTPS).

**Victim (answer)**: IP `10.11.26.183` · Hostname `DESKTOP-B8TQK49` · MAC `d0:57:7b:ce:fc:8b` · User `oboomwald` · Domain `nemotodes.health`

#### True Positives ✅ (v9 — all bugs fixed)
| Finding | Evidence |
|---|---|
| Victim IP `10.11.26.183` | Correctly identified |
| Hostname `DESKTOP-B8TQK49` | ✅ **FIXED** — mDNS `.local` query parsing |
| MAC `d0:57:7b:ce:fc:8b` | ✅ **FIXED** — mac_to_ip reverse lookup (off-by-one bug fixed) |
| Windows user `oboomwald` | Correctly extracted from Kerberos |
| C2 IP `194.180.191.64` in IOC | ✅ **FIXED** — HTTP POST destination IPs added to IOC extraction |
| RAT C2 technique identified | ✅ **FIXED** — T1219 score 1.0 HIGH (68 HTTP pkts on port 443, 58 POSTs) |
| `fakeurl.htm` files hashed | Phase 5 extracted all 71 files including the RAT payloads |
| Domain `nemotodes.health` | Partially — extracted as `nemotodes` from Kerberos realm (FQDN not in Kerberos) |

#### False Negatives ❌ (remaining)
| Item | Root Cause | Fix |
|---|---|---|
| Delivery domains `classicgrand.com`, `modandcrackedapk.com` not flagged | Each had only 1 DNS query — below any diversity threshold | Add single-query NXDOMAIN tracking; need separate signal for rarely-queried external domains |
| `netsupportsoftware.com` not flagged | Same — 1 unique FQDN | Same fix |
| Domain shows `nemotodes` not `nemotodes.health` | Kerberos realm is NetBIOS name; FQDN only visible in SMB paths | Parse full domain from SMB server hostnames (`\\SERVER.domain.tld\`) |

#### Previously False Positives — Now Fixed ✅
| Finding | v8 Score | v9 Score | Fix Applied |
|---|---|---|---|
| T1048.001 DNS TXT Exfil | 1.0 (HIGH) | 0.37 (LOW) | SRV filter + .local exclusion + first-label length gate |
| T1071.004 DNS Tunneling | 0.8 (HIGH) | below threshold (not shown) | Same DNS filter fixes |
| T1003.006 DCSync | HIGH/score 1.0 | MEDIUM/score 1.0 | DCSync gate: drsuapi from non-DC hosts only |

#### Score (v9)
- Victim identification: **4/5** (IP ✅, user ✅, hostname ✅, MAC ✅, domain ❌ partial)
- IOC identification: **1/3** (C2 IP ✅, delivery domains ❌, RAT domain ❌)
- Attack chain detection: **T1219 RAT C2 correctly identified at HIGH confidence** ✅
- Artifacts: **strong** — 71 fakeurl.htm files extracted and hashed correctly
- **Overall: ~7/10** — up from 5/10; primary technique now correctly identified

#### Remaining Gaps (next sprint)
- Single-query suspicious domain detection (delivery domains)
- Full domain from SMB path parsing
- Kerberoasting gate (T1558.003 FP: 6 TGS requests = normal auth, not Kerberoasting)

---

## What Is Working (smoke-tested, not formally verified)

- Full pipeline runs end-to-end in ~3-4s on forensic exercise PCAPs
- Zeek integration: parses conn, dns, ssl, http, smb, kerberos, x509, smb_files
- Kerberoasting signals (RC4 TGS, SPN count, preauth failures) detected
- DCSync detected via `drsuapi` protocol presence
- Port scan detection with tiered S0/REJ/RSTO counting
- DNS tunneling: entropy, TXT ratio, NXDOMAIN rate, subdomain diversity
- SMB lateral movement: admin share paths, host count
- RITA beacon scoring: synthetic test at 60s interval → score 0.834 ✓
- RITA negative test: random traffic → score 0.0 (no FP) ✓
- TLS cert anomaly detection: self-signed, generic CN, known malicious fingerprint
- SMB file extraction from smb_files.log
- Artifact extraction: 71 HTTP files extracted and SHA256-hashed from 2024-11-26 PCAP
- Wireshark filters: all 8 sections generated with real IPs from PCAP context
- Reporter: executive summary prose, victim details (Kerberos user), structured IOC table

---

## Gaps & Missing Features

### Critical (blocks detection quality)
| Gap | Impact | Sprint |
|---|---|---|
| ~~Zeek JA3 package not installed~~ | ~~TLS fingerprinting unavailable~~ | ✅ 9A done |
| ~~Suricata not installed~~ | ~~Zero signature-layer detection~~ | ✅ Done |
| ~~No formal verification~~ | ~~Can't claim correctness~~ | ✅ 5 PCAPs verified |
| ~~9 playbooks missing~~ | ~~30% TTP coverage absent~~ | ✅ 10A done, 30/30 |
| ~~Single-query suspicious domain detection~~ | ~~Delivery domains with 1 DNS query missed (classicgrand.com etc.)~~ | ✅ Sprint 11A — `_is_suspicious_singleton()` heuristic + Anomaly 6 + 28 unit tests |
| Full domain from SMB path parsing | Kerberos realm is NetBIOS not FQDN; SMB paths have full domain | 11B |

### Important (reduces coverage)
| Gap | Impact | Sprint |
|---|---|---|
| Sigma rules not integrated | No log-level signature detection | 9B |
| ~~RITA Docker wrapper~~ | ~~Gold-standard beacon scoring not available~~ | ✅ Sprint 9C done |
| No HTML report | Blueprint specifies HTML output | TBD |
| TAXII/MITRE utils | No live ATT&CK data pull | TBD |
| ACTMINER sequence scoring | Temporal ordering reduces FP by ~39% | TBD |
| Community ID | Cross-tool pivoting (Zeek↔Suricata↔tshark) | TBD |

### Testing
| Gap | Sprint |
|---|---|
| `tests/` directory is empty — no automated tests | 10B |
| No PCAP→answer comparison harness | **NOW** |
| No CI/CD pipeline | TBD |

---

## Sprint 11 — Expert Audit Findings (2026-05-12)

Full skeptic review surfaced the issues below. Each is tracked to a fix sprint.

### CRITICAL — Breaks Correctness Claims

| # | Issue | File | Status |
|---|---|---|---|
| C1 | FFT applied to non-resampled IAT sequence — IATs are non-uniform; rfft on them produces meaningless frequency estimates. Comment even says "resample first" but never does it. | `phase2_beacon.py:128` | ✅ Fixed Sprint 11 |
| C2 | `confidence_ceiling` field in playbooks (e.g. T1071) is read from YAML but **never enforced** in scorer — any playbook can return CONFIRMED even if the author capped it at HIGH | `scorer.py` | ✅ Fixed Sprint 11 |
| C3 | Zero test coverage — `tests/` contains only `.gitkeep`. No unit tests, no integration tests. Every regression is invisible. | `tests/` | ✅ Partial fix Sprint 11 (scorer + beacon unit tests written) |

### HIGH — Misleading to Consumers

| # | Issue | File | Status |
|---|---|---|---|
| H1 | `--no-ai` flag implies AI inference runs; `phase7_anomaly.py` is purely heuristic Python, no LLM called. The `ai_prompt` field is written to JSON but never sent anywhere. | `main.py`, `phase7_anomaly.py` | ✅ Fixed Sprint 11 (flag renamed + help text corrected) |
| H2 | "Under 15 seconds" runtime claim is offline-only. With `VT_INTERVAL=16s` and default 10 IPs, online enrichment adds **160+ seconds** — not disclosed in README pitch. | `README.md` | ✅ Fixed Sprint 11A |
| H3 | Scorer weights are arbitrary — no ROC analysis, no empirical FP/TP basis. `_confidence()` thresholds (n≥3, c≥2 → HIGH) are convention, not statistics. Score of 0.60 means different things across playbooks. | `scorer.py` | 🔲 Requires empirical tuning sprint |
| H4 | JA3 list contains `5d41402abc4b2a76b9719d911017c592` — the MD5 hash of the string `"hello"`, labelled "Metasploit reverse_tcp stager". Will false-positive any session hashing to this value. | `phase6_ioc_enrichment.py:39` | ✅ Fixed Sprint 11 |

### MEDIUM — Architectural Gaps

| # | Issue | File | Status |
|---|---|---|---|
| M1 | Anomaly thresholds are magic numbers with no calibration: `dns_nxdomain_rate >= 0.20`, `tls_missing_sni >= 5`, etc. Real environments have wildly different baselines; these are false-positive generators. | `phase7_anomaly.py` | 🔲 Sprint 11B — tie to calibrator |
| M2 | Single-victim assumption — engine picks one victim IP and all analysis centers on it. Multi-host captures with lateral movement between several victims silently lose non-primary activity. | `phase1_orientation.py`, `reporter.py` | 🔲 Sprint 12 architectural work |
| M3 | No structured logging — entire pipeline uses `print()`. Cannot integrate with log aggregators, replay analysis runs, or grep for warnings. | all phases | 🔲 Sprint 12 |
| M4 | No resource limits — no PCAP size check, no subprocess timeout on Zeek. A malformed or very large capture will OOM or hang indefinitely. | `phase2_protocol.py`, `utils/zeek.py` | 🔲 Sprint 11B |
| M5 | JA3 list is static with no update mechanism and no per-entry provenance. No reference to original source for each hash. | `phase6_ioc_enrichment.py` | ✅ Partially fixed Sprint 11 (bad hash removed; provenance comments added) |

### LOW — Code Quality

| # | Issue | File | Status |
|---|---|---|---|
| L1 | `warnings.filterwarnings("ignore")` suppresses ALL Python warnings globally, masking real dependency issues. | `main.py:15` | ✅ Fixed Sprint 11 (targeted filter) |
| L2 | `false_positive_notes` field in playbook YAML is never read by scorer or reporter — FP guidance written by playbook authors is invisible in the output report. | `scorer.py`, `reporter.py` | ✅ Fixed Sprint 11 |
| L3 | No encrypted-DNS (DoH/DoT) or IPv6 coverage — modern C2 increasingly uses DoH to bypass all DNS signal computation. | multiple | 🔲 Sprint 13 research spike |
| L4 | `sys.path.insert` in main.py instead of proper `pyproject.toml` package — prevents `pip install -e .`, breaks imports from arbitrary working directories. | `main.py:18` | 🔲 Sprint 11B (add pyproject.toml) |

---

## README Accuracy Audit (2026-05-12)

Live test run against `28-02-sample.pcap` with `--max-iocs 5` (online mode, all APIs enabled).
Total runtime: **79.4 seconds** (69.4s in Phase 6 alone).

### Verified Claims ✅

| Claim | Result |
|---|---|
| 30 MITRE ATT&CK TTPs in playbooks | ✅ Confirmed — 30 loaded, all scored |
| Suricata boost +0.10 to TTP score on signature match | ✅ Confirmed in phase3_ttp_sweep.py |
| VT rate limit 4 req/min (16s interval) | ✅ Confirmed — vt_client.py `_MIN_INTERVAL=15.0` |
| All 4 output files produced (report.md, findings.json, anomalies.json, wireshark_filters.md) | ✅ Confirmed |
| Victim identification: IP, hostname, MAC, user, domain | ✅ Confirmed across all 5 verified PCAPs |
| C2 IP `45.131.214.85` confirmed MALICIOUS: VT 12 engines, ThreatFox `NetSupportManager RAT` | ✅ Online mode working |
| `anomalies.json` contains `ai_prompt` and `ai_hypothesis` fields | ✅ Fields present (hypothesis empty if quota exhausted) |
| false_positive_notes from playbook YAML surfaced in report | ✅ Fixed Sprint 11 |
| confidence_ceiling enforced by scorer | ✅ Fixed Sprint 11 |
| IOC "Not enriched" note for IPs beyond max-iocs limit | ✅ Present but wording misleading — see gap R7 |

### False or Misleading Claims ❌

| # | Claim in README | Reality | Fix Sprint |
|---|---|---|---|
| R1 | "in under 15 seconds" (headline, README line 2) | TRUE only offline. Online with 5 IPs = **79s** (VT adds 16s/IP). 10 IPs = ~160s, 20 IPs = ~320s. | ✅ Fixed Sprint 11A — "under 2 minutes on a laptop" |
| R2 | "four independent detection layers" (detection layer table) | **Five** layers exist: Behavioral (Playbooks), Signatures (Suricata), Beacon Scoring, JA3, AND **Sigma** (added Sprint 9B). Sigma is completely absent from the README detection matrix. | ✅ Fixed Sprint 11A — Sigma row added; header updated to "five" |
| R3 | RITA "4-factor composite: **jitter, skew, top-connected, connections/hour** + FFT" | These are RITA's original factor names. Actual implementation uses: **interval_score** (CV of IATs), **size_score** (CV of payload bytes), **freq_score** (histogram fraction near modal interval), **persist_score** (duration/4h). "Skew" and "top-connected" are not computed; "connections/hour" is not the persist formula. | ✅ Fixed Sprint 11A — table and inline description updated to actual factor names |
| R4 | "IPs from TTP findings ← VirusTotal + ThreatFox (prioritised)" (IOC Enrichment table) | `_priority_ips()` in phase6 uses `scan_candidates`, `top_talkers`, and `ctx.external_ips` — not TTP finding objects. No code path extracts IPs directly from `TTPScore` results. | Correct IOC enrichment description or implement the TTP-IP extraction |
| R5 | "AI analysis" in the Anomaly Layer row of Detection Coverage Matrix | Previously a lie — no LLM was called. **Fixed Sprint 11**: Gemini integration now wired. Hypothesis appears in report and `anomalies.json` when key is set and quota available. | ✅ Fixed |
| R6 | "Max 20 IPs per run" (IOC section) | `MAX_IPS=20` in phase6 code, but CLI default is `--max-iocs 10`. README says 20; tool defaults to 10. | ✅ Fixed Sprint 11A — README updated to "default 10 (configurable with --max-iocs)" |
| R7 | "Not enriched (run without `--offline`)" note for un-enriched IPs | Message fires even in online mode when max-iocs limit is hit. Wrong cause stated. | Fix message to say "max-iocs limit reached" vs "run offline" |

### Output Content Gaps (what README claims outputs contain vs what they actually contain)

| Gap | File | Description | Fix |
|---|---|---|---|
| G1 | `anomalies.json` | Previously had no `ai_hypothesis` field | ✅ Fixed Sprint 11 |
| G2 | `report.md` Anomaly section | Previously showed no Gemini output | ✅ Fixed Sprint 11 (rendered as `🤖 Gemini Analysis` block) |
| G3 | `report.md` findings | `false_positive_notes` from YAML invisible to analyst | ✅ Fixed Sprint 11 (rendered as blockquote) |
| G4 | `report.md` findings | `confidence_ceiling` cap invisible — analyst couldn't know CONFIRMED was intentionally blocked | ✅ Fixed Sprint 11 (ceiling enforced in scorer) |
| G5 | Detection Coverage Matrix (README) | Sigma layer completely absent despite being a functional detection path | ✅ Fixed Sprint 11A — Sigma row added to detection layers table |

### Online Mode Test Results (2026-05-12, `28-02-sample.pcap`)

```
Runtime breakdown:
  Phase 1 Orientation:   1.7s
  Phase 2 Protocol:      1.6s
  Phase 2.5 Suricata:    3.0s
  Phase 3 TTP Sweep:     0.1s
  Phase 4 Deep Dive:     0.0s
  Phase 5 Artifacts:     0.6s
  Phase 6 IOC Enrich:   69.4s  ← 5 IPs × ~16s VT interval
  Phase 7 Anomaly:       3.0s  ← Gemini retry (quota exhausted)
  Report:                0.0s
  TOTAL:                79.4s

VT confirmed:  45.131.214.85  → 12 malicious engines
ThreatFox:     45.131.214.85  → NetSupportManager RAT (confidence not shown in log)
Anomalies:     2 detected (dns_nxdomain_pattern, high_http_post_volume)
Gemini:        QUOTA EXHAUSTED — free tier limit: 0 requests/day on this key
               Retry logic fired once (32s delay), then failed gracefully
```

**Gemini quota note (Sprint 11A update)**: Switched to `GOOGLE_API_GENERAL_KEY` (primary) with `GOOGLE_API_KEY` as fallback, and model updated to `gemini-3.1-flash-lite`. The `GOOGLE_API_GENERAL_KEY` has active quota on `gemini-3.1-flash-lite` and is confirmed working. `gemini-2.0-flash` on both keys has `limit: 0` on the free tier.

---

## Planned Work

### Now — Verification Sprint (BLOCKING)
- [x] Read `2024-11-26-answers.pdf` and compare against `outputs/2024-11-26_v8/report.md` ✅ Done v9
- [x] Run all 5 PCAPs and populate verification matrix above ✅ Done v9
- [x] Document FP/FN findings; tune signal weights if needed ✅ Done v9

### Sprint 9A — Zeek JA3 ✅ COMPLETE
- [x] `zkg install zeek/salesforce/ja3` — JA3/JA3S now in ssl.log via `packages` keyword
- [x] JA3 hash lookup in Phase 6 — `check_ja3()` offline; known-bad list: CS, Meterpreter, RATs
- [x] JA3 section in report (active/inactive status, match table)
- [x] Add `tls_unique_ja3_count` signal to T1573.001 playbook — `diverse_ja3_fingerprints` signal + combo bonus + 5 unit tests ✅

### Sprint 9B — Sigma Rules ✅ COMPLETE
- [x] Sparse clone `SigmaHQ/sigma` — 21 network/zeek rules in `sigma/rules/network/zeek/`
- [x] Install `sigma-cli` + pySigma (no Zeek backend exists — built custom DataFrame evaluator)
- [x] `utils/sigma.py` — parses Sigma YAML via pySigma, evaluates conditions against Zeek DataFrames
- [x] Feed results as signal boosters in Phase 3 (same +0.10 boost mechanic as Suricata)
- [x] Phase 2.6 in main.py + Sigma Rule Scan section in report

### Sprint 9C — RITA Docker Wrapper ✅ COMPLETE
- [x] `setup/docker-compose.yml` — MongoDB 4.2 (required by RITA 4.3.1)
- [x] `engine/utils/rita.py` — full pipeline: start mongo, import Zeek logs, `show-beacons`, parse CSV
- [x] `rita_available`, `rita_top_beacon_score`, `rita_beacon_pairs`, `rita_beacons` added to ProtocolSignals
- [x] Graceful skip when Docker not running (`is_available()` check)
- [x] Report section shows RITA results (or "not available" note) above in-engine scoring
- [x] Tested end-to-end: Colima + Docker + mongo:4.2 + RITA 4.3.1 — import + query runs cleanly

**Setup notes:**
- Requires Colima (`brew install colima && colima start`)
- Requires docker + docker-compose (`brew install docker docker-compose`)
- MongoDB 4.2 auto-started by rita.py; RITA image `activecm/rita:4.3.1` pulled on first use
- `mongo:4.2` used (not `mongo:6`) — RITA 4.3.1 requires MongoDB [4.2.0, 4.3.0)
- Config written to `~/.cache/rita_pcap_engine/` (must be under /Users for Colima volume mount)

### Sprint 10A — 8 More Playbooks (reach 30) ✅ COMPLETE
- [x] T1550.002 Pass-the-Hash — smb_lateral_host_count, admin_share_detected, low kerberos gate
- [x] T1595 Active Scanning — inbound_scan_unique_src_count (new signal), scan_syn_only_count
- [x] T1132.001 Base64 Data Encoding — dns_base64_label_count + http_base64_uri_count (new signals)
- [x] T1016 Network Config Discovery — dns_ptr_lookup_count (new signal), ldap, cldap
- [x] T1021.006 WinRM — winrm_connection_count (new signal), smb lateral corroboration
- [x] T1572 Protocol Tunneling — dns tunnel + icmp large payload + http port mismatch (composite)
- [x] T1102 Web Service C2 — dns_c2_service_lookup_count (new signal: Telegram/Discord/Pastebin)
- [x] T1036.005 Masquerading — http_on_nonstandard_port + tls_missing_sni + cert anomaly

### Sprint 10B — Test Infrastructure
- [ ] `tests/test_scorer.py` — unit tests for signal evaluation, tiered thresholds
- [ ] `tests/test_beacon.py` — beacon scoring determinism tests
- [ ] `tests/test_integration.py` — run engine against known PCAP, assert key findings
- [ ] `run_tests.sh` wrapper

### Later / Stretch Goals
- HTML report output (add Jinja2 template)
- ACTMINER temporal sequence scoring
- Community ID wiring (Zeek + Suricata correlation)
- Live capture mode (`-i <interface>` instead of `-r <pcap>`)
- Dashboard / web UI for findings

---

## Dependencies (system)

| Tool | Required | Status |
|---|---|---|
| tshark (Wireshark) | ✅ Required | Must be installed |
| Zeek | ✅ Required | Must be installed (`brew install zeek`) |
| Python 3.9+ | ✅ Required | With pandas, numpy, scipy, pyyaml |
| Suricata | Optional | `brew install suricata` for signature detection |
| Docker/Colima | Optional | For RITA beacon scoring |
| zkg (Zeek pkg mgr) | Optional | For JA3 fingerprinting |
| sigma-cli | Optional | For Sigma rule matching |
