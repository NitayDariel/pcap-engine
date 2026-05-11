# Design Decisions & Core Reasoning
# Private — internal reference only.

---

## 1. How We Identify Victim vs Attacker — and When

**Phase 1 — IP partitioning (structural, always correct)**
RFC1918 = internal. Everything else = external. In forensic PCAPs the victim is
always the internal IP. Breaks for insider threat or attacker-already-inside scenarios
— known limitation, acceptable for exercise/SOC triage use case.

**Phase 1 — Victim candidate (heuristic, correct for single-host PCAPs)**
Internal IP with highest outbound byte volume = primary victim. PCAPs are captured
from/near the infected machine so it dominates traffic. Fails if multiple hosts in capture.

**Phase 2 — Identity confirmation (strongest evidence, cascade priority)**
Kerberos CNameString → Windows user (most reliable, from auth protocol)
DHCP / mDNS → hostname · ARP → MAC · SMB share paths → domain FQDN
Machine accounts (ending $) filtered before extracting the human user.

**Phase 3 + Suricata — "Attacker" = C2 infrastructure, not threat actor**
We identify: the external IPs receiving victim callbacks, domains in Suricata alerts.
We do NOT attribute to a threat actor. That requires OSINT beyond a single PCAP.

---

## 2. Why These 6 MITRE Tactics — Not the Other 8

Selection rule: we only model what has a **reliable, falsifiable network signal**.

### Covered ✓
- **TA0011 C2** — C2 IS the network. Richest detection surface. 11 playbooks.
- **TA0006 Credential Access** — Kerberoasting, DCSync, sniffing: all protocol-visible.
- **TA0007 Discovery** — Port scans, LDAP queries, share enum: clear conn.log traces.
- **TA0008 Lateral Movement** — SMB/RDP/WinRM internal hops: obvious in Zeek.
- **TA0010 Exfiltration** — Volume anomalies, DNS tunneling: measurable in PCAP.
- **TA0043 Reconnaissance** — Inbound scanning: external IPs hitting many ports.

### Not Covered ✗ — Reasoning

- **TA0042 Resource Development** — Attacker infra setup happens PRE-attack, never
  visible in victim PCAP. Confident permanent exclusion.

- **TA0002 Execution** — Process creation, PowerShell = endpoint-only. Zero network
  signal except WMI remote (port 135), already captured under Lateral Movement.

- **TA0003 Persistence** — Registry, scheduled tasks, services = endpoint filesystem.
  C2 check-ins post-persistence are indistinguishable from normal C2 (already covered).

- **TA0009 Collection** — Staging happens locally BEFORE exfil. By the time data
  hits the network it's Exfiltration (TA0010), which we cover.

- **TA0005 Defense Evasion** — We partially cover this already: T1036.005
  (Masquerading) is tagged TA0005. Broader evasion (AV kill, log wipe) = endpoint-only.

- **TA0001 Initial Access** — NEED TO DIVE DEEPER. Some IA IS network-visible:
  EternalBlue port-445 exploit traffic, drive-by HTTP, phishing link click → HTTP GET
  to malicious domain. We currently catch zero of this. Delivery domains with single
  DNS queries (classicgrand.com in 2024-11-26) are a known false-negative. A
  "rarely-queried suspicious domain" signal could partially address this. Sprint candidate.

- **TA0004 Privilege Escalation** — NEED TO DIVE DEEPER. Mostly local exploits.
  BUT: Kerberos-based privesc (Golden/Silver Ticket, AS-REP Roasting) IS network-
  visible. Our T1558.003 Kerberoasting playbook is filed under Credential Access —
  there is unresolved tactic overlap. We may be covering Kerberos privesc without
  formally claiming it. Needs clarification before expanding.

- **TA0040 Impact** — NEED TO DIVE DEEPER. DDoS outbound = traffic volume spikes.
  Ransomware C2 key exchange before encryption often uses HTTP/HTTPS. We catch none
  of this today. Worth a sprint if we encounter ransomware PCAPs.

---

## 3. FP Reduction Philosophy

Tiered scoring (not binary) avoids cliff edges: one packet below threshold = zero
score is wrong. Partial credit + combination bonuses reward corroborated signals.
The anomaly layer exists so we never tune a signal to never-FP (which also means
never-TP). Score what we're confident about; surface the rest for human/AI review.

---

## 4. Known Gaps as of v10.2

- Single-query suspicious domains (delivery domains with 1 DNS query go undetected)
- Full domain FQDN from SMB paths (Kerberos realm is NetBIOS, not .domain.tld)
- TA0001 Initial Access detection feasible but not started — sprint candidate
- TA0040 Impact / ransomware detection — not started
- TA0004 Privilege Escalation Kerberos overlap with TA0006 unresolved
- Automated test suite — tests/ directory is empty
