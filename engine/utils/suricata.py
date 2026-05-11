"""
Suricata offline PCAP scanner.
Runs suricata in offline mode against a PCAP, parses eve.json for alerts,
and maps alert signatures to MITRE ATT&CK technique IDs.

Fails gracefully if suricata is not installed — returns empty results.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SURICATA_BIN = shutil.which("suricata") or "/opt/homebrew/bin/suricata"

# ---------------------------------------------------------------------------
# Signature prefix → MITRE ATT&CK technique mapping.
# Ordered by specificity (more specific prefixes first).
# ---------------------------------------------------------------------------
_SIG_TO_MITRE: list[tuple[str, str]] = [
    # DNS-based
    ("ET DNS POSSIBLE DNS TUNNEL", "T1071.004"),
    ("ET DNS Query to a *.TK Domain", "T1568.002"),
    ("ET DNS Suspicious Lookup", "T1071.004"),
    ("ET DNS", "T1071.004"),

    # Scanning
    ("ET SCAN NMAP", "T1046"),
    ("ET SCAN Masscan", "T1046"),
    ("ET SCAN", "T1046"),

    # C2 / Malware
    ("ET TROJAN Cobalt Strike", "T1071"),
    ("ET TROJAN Metasploit", "T1059"),
    ("ET TROJAN", "T1071"),
    ("ET MALWARE", "T1071"),

    # Lateral movement
    ("ET SMB", "T1021.002"),
    ("ET NETBIOS", "T1021.002"),

    # Credential access
    ("ET CREDENTIAL", "T1078"),
    ("ET WEB_SERVER SQL Injection", "T1190"),
    ("ET WEB_SERVER", "T1190"),

    # Kerberos
    ("ET POLICY Kerberos", "T1558"),

    # Exfil
    ("ET POLICY FTP", "T1048"),
    ("ET POLICY Cleartext", "T1040"),
    ("ET POLICY", "T1071"),

    # Exploit
    ("ET EXPLOIT", "T1190"),

    # Info disclosure
    ("ET INFO", "T1082"),

    # Catch-all
    ("GPL", "T1059"),
]


def _signature_to_mitre(signature: str) -> Optional[str]:
    """Map a Suricata alert signature string to a MITRE ATT&CK technique ID."""
    sig_upper = signature.upper()
    for prefix, technique in _SIG_TO_MITRE:
        if prefix.upper() in sig_upper:
            return technique
    return None


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

@dataclass
class SuricataAlert:
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    signature: str
    signature_id: int
    severity: int         # 1=high, 2=medium, 3=low in ET Open
    category: str
    mitre_technique: Optional[str]


@dataclass
class SuricataResult:
    available: bool = False        # False if suricata is not installed
    alerts: list[SuricataAlert] = field(default_factory=list)
    unique_techniques: set[str] = field(default_factory=set)
    alert_count: int = 0
    high_severity_count: int = 0
    rules_path: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Rules management
# ---------------------------------------------------------------------------

_RULES_DIR = Path.home() / ".cache" / "pcap-engine" / "suricata-rules"
_ET_OPEN_URL = (
    "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"
)
_BUNDLED_RULES = """\
# Minimal bundled rules for offline operation — augmented by ET Open when available
alert dns $HOME_NET any -> any any (msg:"ET DNS POSSIBLE DNS TUNNEL Unusually long TXT record"; dns.query; content:"|00 10|"; classtype:trojan-activity; sid:2017516; rev:4; metadata:affected_product Any,attack_target Client_Endpoint,mitre_tactic_id TA0011,mitre_technique_id T1071.004;)
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Cobalt Strike Beacon Activity"; flow:established,to_server; content:"Accept: */*|0d 0a|"; content:"Content-Type: application/octet-stream"; classtype:trojan-activity; sid:2019659; rev:4; metadata:mitre_technique_id T1071;)
alert tcp any any -> $HOME_NET any (msg:"ET SCAN NMAP OS Detection Probe"; flags:A; ack:0; classtype:network-scan; sid:2000537; rev:9; metadata:mitre_technique_id T1046;)
alert smb any any -> $HOME_NET 445 (msg:"ET SMB Possible PSEXEC-Style Lateral Movement"; flow:established,to_server; content:"|ff 53 4d 42|"; classtype:trojan-activity; sid:2019714; rev:2; metadata:mitre_technique_id T1021.002;)
alert dns $HOME_NET any -> any 53 (msg:"ET DNS Potential DGA Domain Lookup"; dns.query; pcre:"/^[a-z0-9]{12,20}\\.(?:com|net|org|ru|cn)$/"; classtype:bad-unknown; sid:2024792; rev:2; metadata:mitre_technique_id T1568.002;)
"""


def _ensure_rules() -> Path:
    """Return path to a valid rules file. Downloads ET Open or uses bundled."""
    _RULES_DIR.mkdir(parents=True, exist_ok=True)
    et_rules = _RULES_DIR / "emerging-all.rules"
    bundled = _RULES_DIR / "minimal.rules"

    if et_rules.exists() and et_rules.stat().st_size > 100_000:
        return et_rules

    # Try to download ET Open rules
    try:
        import urllib.request
        print(f"  [Suricata] Downloading ET Open rules to {et_rules} ...")
        urllib.request.urlretrieve(_ET_OPEN_URL, et_rules)
        print(f"  [Suricata] Rules downloaded ({et_rules.stat().st_size:,} bytes)")
        return et_rules
    except Exception as e:
        print(f"  [Suricata] ET Open download failed ({e}), using bundled minimal rules")
        bundled.write_text(_BUNDLED_RULES)
        return bundled


def _build_suricata_yaml(rules_file: Path, log_dir: Path) -> Path:
    """Write a minimal suricata.yaml for offline PCAP analysis."""
    yaml_path = log_dir / "suricata.yaml"
    yaml_content = f"""
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502

default-log-dir: {log_dir}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: no
            packet: no
            metadata: yes

logging:
  default-log-level: warning
  outputs:
    - console:
        enabled: no
    - file:
        enabled: yes
        level: info
        filename: suricata.log

pcap:
  - interface: eth0

pfring:
  enabled: no

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    dns:
      enabled: yes
    smtp:
      enabled: yes
    smb:
      enabled: yes
    ssh:
      enabled: yes

host-os-policy:
  windows: [0.0.0.0/0]

defrag:
  memcap: 64mb

flow:
  memcap: 64mb

stream:
  memcap: 64mb
  checksum-validation: no

engine-analysis:
  rules-fast-pattern: yes

rule-files:
  - {rules_file}

classification-file: /dev/null
reference-config-file: /dev/null

coredump:
  max-dump: unlimited
"""
    yaml_path.write_text(yaml_content.strip())
    return yaml_path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_available() -> bool:
    """Return True if suricata binary is on PATH."""
    return bool(shutil.which("suricata") or Path(SURICATA_BIN).exists())


def run(pcap_path: str, timeout: int = 180) -> SuricataResult:
    """
    Run suricata in offline mode against pcap_path. Returns SuricataResult.
    If suricata is not installed, returns SuricataResult(available=False).
    """
    if not is_available():
        return SuricataResult(
            available=False,
            error="suricata not found — install with: brew install suricata",
        )

    pcap = Path(pcap_path).resolve()
    if not pcap.exists():
        return SuricataResult(available=True, error=f"PCAP not found: {pcap}")

    result = SuricataResult(available=True)

    with tempfile.TemporaryDirectory(prefix="suricata_") as tmpdir:
        log_dir = Path(tmpdir)
        try:
            rules_file = _ensure_rules()
            result.rules_path = str(rules_file)
        except Exception as e:
            result.error = f"Rules setup failed: {e}"
            return result

        yaml_file = _build_suricata_yaml(rules_file, log_dir)

        cmd = [
            SURICATA_BIN,
            "-c", str(yaml_file),
            "-r", str(pcap),
            "--runmode=single",
            "-l", str(log_dir),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            result.error = f"Suricata timed out after {timeout}s"
            return result
        except Exception as e:
            result.error = str(e)
            return result

        eve_path = log_dir / "eve.json"
        if not eve_path.exists():
            result.error = "No eve.json produced — check suricata rules"
            return result

        alerts: list[SuricataAlert] = []
        try:
            for line in eve_path.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") != "alert":
                    continue

                alert_info = event.get("alert", {})
                sig = alert_info.get("signature", "")
                mitre = _signature_to_mitre(sig)

                alerts.append(
                    SuricataAlert(
                        timestamp=event.get("timestamp", ""),
                        src_ip=event.get("src_ip", ""),
                        src_port=int(event.get("src_port", 0)),
                        dst_ip=event.get("dest_ip", ""),
                        dst_port=int(event.get("dest_port", 0)),
                        proto=event.get("proto", ""),
                        signature=sig,
                        signature_id=int(alert_info.get("signature_id", 0)),
                        severity=int(alert_info.get("severity", 3)),
                        category=alert_info.get("category", ""),
                        mitre_technique=mitre,
                    )
                )
        except Exception as e:
            result.error = f"eve.json parse error: {e}"

        result.alerts = alerts
        result.alert_count = len(alerts)
        result.high_severity_count = sum(1 for a in alerts if a.severity == 1)
        result.unique_techniques = {a.mitre_technique for a in alerts if a.mitre_technique}

    return result
