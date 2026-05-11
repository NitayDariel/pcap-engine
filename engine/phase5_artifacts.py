"""
Phase 5 — Artifact Extraction.

Extracts three classes of forensic artifacts:
  1. File transfers   — tshark --export-objects (HTTP, SMB, DICOM, etc.)
                        Each extracted file is SHA256-hashed.
  2. TLS certificates — parsed from Zeek x509.log (fingerprint, subject, issuer, SANs)
  3. SMB file paths   — parsed from Zeek smb_files.log (files touched during lateral movement)

Results feed into:
  - reporter.py   (new "Artifacts" section)
  - phase6_ioc_enrichment.py (SHA256 hashes passed to VT file lookup)
  - IOC table at top of report

Called between Phase 4 (deep dive) and Phase 6 (IOC enrichment).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from engine.utils.zeek import parse_log


# ---------------------------------------------------------------------------
# Output structures
# ---------------------------------------------------------------------------

@dataclass
class ExtractedFile:
    filename: str
    sha256: str
    size_bytes: int
    mime_type: str
    protocol: str          # HTTP, SMB, etc.
    src_ip: str
    dst_ip: str
    url: str               # HTTP URL or UNC path


@dataclass
class TLSCertificate:
    fingerprint: str       # Zeek fingerprint (SHA-256 of DER)
    subject: str
    issuer: str
    san_dns: list[str]
    not_valid_before: float
    not_valid_after: float
    key_type: str
    key_length: int
    is_ca: bool
    anomalies: list[str]   # e.g. ["self-signed", "expired", "long_validity"]


@dataclass
class SMBFileEvent:
    ts: float
    src_ip: str
    dst_ip: str
    path: str              # UNC path like \\SERVER\share\file.exe
    action: str            # WRITE, READ, DELETE
    size_bytes: int


@dataclass
class ArtifactResult:
    extracted_files: list[ExtractedFile] = field(default_factory=list)
    tls_certificates: list[TLSCertificate] = field(default_factory=list)
    smb_file_events: list[SMBFileEvent] = field(default_factory=list)
    extraction_errors: list[str] = field(default_factory=list)

    @property
    def sha256_hashes(self) -> list[str]:
        return [f.sha256 for f in self.extracted_files]

    @property
    def suspicious_certs(self) -> list[TLSCertificate]:
        return [c for c in self.tls_certificates if c.anomalies]

    @property
    def suspicious_smb_writes(self) -> list[SMBFileEvent]:
        return [e for e in self.smb_file_events if e.action == "WRITE"]


# ---------------------------------------------------------------------------
# File extraction via tshark
# ---------------------------------------------------------------------------

_TSHARK_BIN = "tshark"
_EXPORT_PROTOCOLS = ["http", "smb", "dicom", "tftp"]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_files(pcap_path: str, files_log_df, result: ArtifactResult) -> None:
    """
    Run tshark --export-objects for each supported protocol.
    Hash each extracted file and record as ExtractedFile.

    files_log_df is the Zeek files.log DataFrame — used to map MIME types to filenames.
    """
    pcap = Path(pcap_path)

    # Build a quick lookup: (src_ip, dst_ip, filename) → mime_type from Zeek
    mime_lookup: dict[str, str] = {}
    url_lookup: dict[str, str] = {}
    if files_log_df is not None and not files_log_df.empty:
        for _, row in files_log_df.iterrows():
            fname = str(row.get("filename", ""))
            if fname and fname != "nan":
                key = fname.lower()
                mime_lookup[key] = str(row.get("mime_type", "application/octet-stream"))

    with tempfile.TemporaryDirectory(prefix="tshark_extract_") as tmpdir:
        tmp = Path(tmpdir)

        for proto in _EXPORT_PROTOCOLS:
            proto_dir = tmp / proto
            proto_dir.mkdir()

            try:
                cmd = [
                    _TSHARK_BIN,
                    "-r", str(pcap),
                    "--export-objects", f"{proto},{proto_dir}",
                    "-q",
                ]
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                result.extraction_errors.append(f"tshark export-objects {proto}: {e}")
                continue

            for extracted in proto_dir.iterdir():
                if not extracted.is_file():
                    continue
                try:
                    sha = _sha256_file(extracted)
                    size = extracted.stat().st_size
                    fname = extracted.name
                    mime = mime_lookup.get(fname.lower(), "application/octet-stream")

                    result.extracted_files.append(
                        ExtractedFile(
                            filename=fname,
                            sha256=sha,
                            size_bytes=size,
                            mime_type=mime,
                            protocol=proto.upper(),
                            src_ip="",  # tshark --export-objects doesn't give us src/dst per file
                            dst_ip="",
                            url=fname,
                        )
                    )
                except Exception as e:
                    result.extraction_errors.append(f"Hash {extracted.name}: {e}")


# ---------------------------------------------------------------------------
# TLS certificate analysis
# ---------------------------------------------------------------------------

_SELF_SIGNED_CERTS = set()  # Certs where subject == issuer
_EPOCH_YEAR_2000 = 946684800.0
_ONE_YEAR_SECS = 365 * 24 * 3600
_TEN_YEARS_SECS = 10 * _ONE_YEAR_SECS

# Known malicious TLS certificate SHA256 fingerprints.
# These are cross-referenced against public threat intel — leave empty to avoid FPs.
# Add verified C2 cert fingerprints here as intelligence is gathered.
_KNOWN_MALICIOUS_CERTS: set[str] = set()


def _cert_anomalies(row: dict, reference_ts: float = 0.0) -> list[str]:
    """
    Classify certificate anomalies from an x509.log row.
    reference_ts: PCAP capture timestamp (seconds since epoch). If provided,
                  "expired" is checked against the capture time, not today.
    """
    anomalies = []
    subject = str(row.get("certificate.subject", ""))
    issuer = str(row.get("certificate.issuer", ""))

    if subject == issuer:
        anomalies.append("self-signed")

    not_after = float(row.get("certificate.not_valid_after", 0))
    not_before = float(row.get("certificate.not_valid_before", 0))

    check_ts = reference_ts if reference_ts > 0 else not_before  # don't check expiry against today
    if not_after > 0 and check_ts > 0 and not_after < check_ts:
        anomalies.append("expired_at_capture_time")

    is_ca = bool(row.get("basic_constraints.ca", False))
    if not is_ca and not_after - not_before > _TEN_YEARS_SECS:
        # Only flag unusually long validity for end-entity certs — root/intermediate CAs are expected
        anomalies.append("unusually_long_validity_leaf_cert")

    # Suspicious subject patterns — generic/random CN
    import re
    if re.match(r"^CN=[a-z]{6,14}$", subject.strip()):
        anomalies.append("generic_cn_looks_generated")

    if row.get("fingerprint", "") in _KNOWN_MALICIOUS_CERTS:
        anomalies.append("known_malicious_cert")

    return anomalies


def _parse_x509(log_dir: str, result: ArtifactResult, reference_ts: float = 0.0) -> None:
    """Parse Zeek x509.log and extract certificate records."""
    x509_df = parse_log(f"{log_dir}/x509.log")
    if x509_df.empty:
        return

    for _, row in x509_df.iterrows():
        row_dict = row.to_dict()
        san_dns = row_dict.get("san.dns", [])
        if not isinstance(san_dns, list):
            try:
                san_dns = json.loads(san_dns) if san_dns else []
            except Exception:
                san_dns = []

        anomalies = _cert_anomalies(row_dict, reference_ts=reference_ts)

        cert = TLSCertificate(
            fingerprint=str(row_dict.get("fingerprint", "")),
            subject=str(row_dict.get("certificate.subject", "")),
            issuer=str(row_dict.get("certificate.issuer", "")),
            san_dns=san_dns[:10],
            not_valid_before=float(row_dict.get("certificate.not_valid_before", 0)),
            not_valid_after=float(row_dict.get("certificate.not_valid_after", 0)),
            key_type=str(row_dict.get("certificate.key_type", "")),
            key_length=int(row_dict.get("certificate.key_length", 0)),
            is_ca=bool(row_dict.get("basic_constraints.ca", False)),
            anomalies=anomalies,
        )
        result.tls_certificates.append(cert)


# ---------------------------------------------------------------------------
# SMB file event analysis
# ---------------------------------------------------------------------------

def _parse_smb_files(log_dir: str, result: ArtifactResult) -> None:
    """Parse Zeek smb_files.log for file write/read events."""
    smb_df = parse_log(f"{log_dir}/smb_files.log")
    if smb_df.empty:
        return

    for _, row in smb_df.iterrows():
        action = str(row.get("action", "")).upper()
        path = str(row.get("path", "")) + "\\" + str(row.get("name", ""))
        path = path.strip("\\")

        ts = float(row.get("ts", 0))
        src = str(row.get("id.orig_h", ""))
        dst = str(row.get("id.resp_h", ""))
        size = int(row.get("size", 0)) if str(row.get("size", "")) not in ("", "nan") else 0

        result.smb_file_events.append(
            SMBFileEvent(
                ts=ts,
                src_ip=src,
                dst_ip=dst,
                path=path,
                action=action,
                size_bytes=size,
            )
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    pcap_path: str,
    zeek_log_dir: str,
    extract_files: bool = True,
    capture_start_ts: float = 0.0,
) -> ArtifactResult:
    """
    Run Phase 5 artifact extraction.

    Args:
        pcap_path: Path to the PCAP file.
        zeek_log_dir: Directory containing Zeek JSON logs from Phase 2.
        extract_files: If True, run tshark --export-objects (can be slow for large PCAPs).

    Returns:
        ArtifactResult with files, certificates, and SMB events.
    """
    result = ArtifactResult()

    # TLS certificates (x509.log)
    try:
        _parse_x509(zeek_log_dir, result, reference_ts=capture_start_ts)
    except Exception as e:
        result.extraction_errors.append(f"x509 parse: {e}")

    # SMB file events (smb_files.log)
    try:
        _parse_smb_files(zeek_log_dir, result)
    except Exception as e:
        result.extraction_errors.append(f"smb_files parse: {e}")

    # File extraction + hashing (tshark --export-objects)
    if extract_files:
        try:
            files_df = parse_log(f"{zeek_log_dir}/files.log")
        except Exception:
            files_df = None
        try:
            _extract_files(pcap_path, files_df, result)
        except Exception as e:
            result.extraction_errors.append(f"file extraction: {e}")

    return result
