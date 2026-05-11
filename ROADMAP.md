# PCAP Engine — Roadmap

> Live document. Update status fields in-place. Last updated: 2026-05-11 (v10 — Sprint 10A complete, 30/30 playbooks)

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
| Phase 2.5 — Suricata | ✅ Implemented | Graceful skip if not installed; ET Open rules |
| Phase 3 — TTP Sweep | ✅ Implemented | Parallel YAML scoring; tiered thresholds; Suricata boost |
| Phase 4 — Deep Dive | ✅ Implemented | Targeted tshark evidence for high-score TTPs |
| Phase 5 — Artifacts | ✅ Implemented | File hashes (tshark), TLS certs (x509.log), SMB events |
| Phase 6 — IOC Enrichment | ✅ Implemented | VirusTotal + ThreatFox; offline-safe |
| Phase 7 — Anomaly Layer | ✅ Implemented | Uncategorised pattern detection |
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
| **2024-09-04** | ✅ v9 | ✅ 172.17.0.99 | ✅ DESKTOP-RNVO9AT | ✅ | ✅ afletcher | ✅ bepositive.com | ✅ 79.124.78.197 | T1219 HIGH | **~8/10** |
| **2024-11-26** | ✅ v9 | ✅ 10.11.26.183 | ✅ desktop-b8tqk49 | ✅ | ✅ oboomwald | ✅ nemotodes.health | ✅ 194.180.191.64 | T1219 HIGH | **~8/10** |
| **2025-01-22** | ✅ v9 | ✅ 10.1.17.215 | ✅ DESKTOP-L8C5GSJ | ✅ | ✅ shutchenson | (unverified) | 2/3 C2 IPs | T1219 LOW | **~7/10** |
| **2026-01-31** | ✅ v9 | ✅ 10.1.21.58 | ✅ DESKTOP-ES9F3ML | ✅ | ✅ gwyatt | ✅ win11office.com | ✅ 153.92.1.49 | T1046 / T1049 | **~7/10** |
| **2026-02-28** | ✅ v9 | ✅ 10.2.28.88 | ✅ DESKTOP-TEYQ2NR | ✅ | ✅ brolf | ✅ easyas123.tech | ✅ 45.131.214.85 | T1219 HIGH | **~8/10** |

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
| Zeek JA3 package not installed | TLS fingerprinting always shows "not installed" | 9A |
| Suricata not installed | Zero signature-layer detection | 9B or manual |
| No formal verification | Can't claim correctness | **MUST DO FIRST** |
| 9 playbooks missing | 30% of target TTP coverage absent | 10A |

### Important (reduces coverage)
| Gap | Impact | Sprint |
|---|---|---|
| Sigma rules not integrated | No log-level signature detection | 9B |
| RITA Docker wrapper | Gold-standard beacon scoring not available | 9C |
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

## Planned Work

### Now — Verification Sprint (BLOCKING)
- [x] Read `2024-11-26-answers.pdf` and compare against `outputs/2024-11-26_v8/report.md` ✅ Done v9
- [x] Run all 5 PCAPs and populate verification matrix above ✅ Done v9
- [x] Document FP/FN findings; tune signal weights if needed ✅ Done v9

### Sprint 9A — Zeek JA3
- [ ] `zkg install zeek/sethhall/ja3` — enable JA3 in Zeek run
- [ ] JA3 hash lookup in Phase 6 (offline: hardcoded known-bad list)
- [ ] Add `tls_unique_ja3_count` signal to relevant playbooks

### Sprint 9B — Sigma Rules
- [ ] Shallow clone `SigmaHQ/sigma` (network/zeek rules only)
- [ ] Install `sigma-cli` + pySigma Zeek backend
- [ ] `utils/sigma.py` — convert rules, run against Zeek logs, map hits to ATT&CK
- [ ] Feed results as signal boosters (like Suricata does)

### Sprint 9C — RITA Docker Wrapper
- [ ] `docker-compose.yml` for RITA + MongoDB
- [ ] `utils/rita.py` — call `show-beacons`, `show-dns`, parse output
- [ ] Add `rita_beacon_score` to ProtocolSignals
- [ ] Only runs if Docker is available (graceful skip otherwise)

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
