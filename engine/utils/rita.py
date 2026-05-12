"""
RITA v4 Docker wrapper for beacon analysis.

Flow:
  1. Verify Docker is accessible (Colima running).
  2. Start MongoDB container on the rita_net bridge (via docker-compose).
  3. Write a minimal RITA config pointing to rita_mongo:27017.
  4. Import Zeek conn.log directory into a RITA database.
  5. Query show-beacons (and optionally show-exploded-dns).
  6. Parse CSV output into structured dataclasses.
  7. Tear down MongoDB container when done.

Gracefully skips (returns RitaResult with available=False) when:
  - Docker daemon is not running / not installed
  - RITA image pull fails
  - Import or query step errors

The pipeline treats RITA as an optional enrichment layer —
its absence never blocks the rest of the analysis.
"""

from __future__ import annotations

import csv
import io
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_RITA_IMAGE = "activecm/rita:4.3.1"
_MONGO_IMAGE = "mongo:4.2"   # RITA 4.3.1 requires MongoDB [4.2.0, 4.3.0)
_MONGO_CONTAINER = "rita_mongo"
_RITA_NETWORK = "rita_net"
_COMPOSE_FILE = str(Path(__file__).resolve().parents[2] / "setup" / "docker-compose.yml")
_MONGO_READY_TIMEOUT = 30   # seconds to wait for MongoDB healthcheck

# Minimal RITA config template — overrides default localhost:27017 so RITA
# inside the container can reach rita_mongo on the rita_net bridge.
_RITA_CONFIG_TEMPLATE = """\
MongoDB:
  ConnectionString: mongodb://{mongo_host}:27017
  AuthenticationMechanism: ""
  SocketTimeout: 2h0m0s
  TLS:
    Enable: false
    VerifyCertificate: false
    CAFile: ""
  MetaDB: MetaDatabase
LogConfig:
  LogLevel: 2
  LogPath: /tmp/rita_log.txt
  LogToFile: false
"""


@dataclass
class BeaconEntry:
    score: float
    src_ip: str
    dst_ip: str
    connections: int
    avg_bytes: float
    top_interval_secs: float
    interval_skew: float
    size_skew: float


@dataclass
class RitaResult:
    available: bool = False
    error: str = ""
    beacons: list[BeaconEntry] = field(default_factory=list)
    top_beacon_score: float = 0.0
    beacon_pairs: int = 0       # number of src→dst pairs above 0.5 score


def is_available() -> bool:
    """True if Docker daemon is reachable."""
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "ps"], capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


def run(zeek_log_dir: str, analysis_name: str = "rita_pcap") -> RitaResult:
    """
    Run RITA against a Zeek log directory and return structured beacon results.
    Returns RitaResult(available=False) on any infrastructure failure.
    """
    if not is_available():
        return RitaResult(available=False, error="Docker not available")

    zeek_path = Path(zeek_log_dir)
    if not zeek_path.exists():
        return RitaResult(available=False, error=f"Zeek log dir not found: {zeek_log_dir}")

    try:
        return _run_pipeline(str(zeek_path.resolve()), analysis_name)
    except Exception as exc:
        return RitaResult(available=False, error=f"RITA pipeline failed: {exc}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_pipeline(zeek_log_dir: str, db_name: str) -> RitaResult:
    """Full pipeline: start mongo → import → query → parse → cleanup."""
    _ensure_rita_image()
    _ensure_mongo_running()

    # Config must live under /Users so Colima's volume mount makes it
    # accessible inside the Docker container. /tmp on macOS is /private/tmp
    # which Colima does NOT mount by default.
    _cache_dir = Path.home() / ".cache" / "rita_pcap_engine"
    _cache_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = str(_cache_dir / f"rita_config_{db_name}.yaml")
    with open(cfg_path, "w") as cfg_file:
        cfg_file.write(_RITA_CONFIG_TEMPLATE.format(mongo_host=_MONGO_CONTAINER))

    try:
        _rita_import(zeek_log_dir, db_name, cfg_path)
        beacons = _rita_show_beacons(db_name, cfg_path)
        _rita_delete_db(db_name, cfg_path)
    finally:
        Path(cfg_path).unlink(missing_ok=True)

    top_score = max((b.score for b in beacons), default=0.0)
    high_confidence = [b for b in beacons if b.score >= 0.5]

    return RitaResult(
        available=True,
        beacons=beacons,
        top_beacon_score=round(top_score, 4),
        beacon_pairs=len(high_confidence),
    )


def _ensure_rita_image() -> None:
    """Pull RITA image if not already present."""
    r = subprocess.run(
        ["docker", "image", "inspect", _RITA_IMAGE],
        capture_output=True, timeout=10
    )
    if r.returncode != 0:
        print(f"  [RITA] Pulling {_RITA_IMAGE}...")
        subprocess.run(
            ["docker", "pull", "--platform", "linux/amd64", _RITA_IMAGE],
            check=True, timeout=120
        )


def _ensure_mongo_running() -> None:
    """Start MongoDB container if not already up; wait for it to accept connections."""
    r = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", _MONGO_CONTAINER],
        capture_output=True, text=True, timeout=10
    )
    if r.returncode == 0 and r.stdout.strip() == "running":
        return  # already up

    # Create the rita_net network if absent
    subprocess.run(
        ["docker", "network", "create", _RITA_NETWORK],
        capture_output=True, timeout=15
    )

    print("  [RITA] Starting MongoDB (rita_mongo)...")
    subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--name", _MONGO_CONTAINER,
            "--network", _RITA_NETWORK,
            _MONGO_IMAGE,
        ],
        check=True, capture_output=True, timeout=60
    )
    _wait_for_mongo()


def _wait_for_mongo() -> None:
    # mongo:4.2 uses legacy `mongo` shell (not `mongosh`)
    deadline = time.time() + _MONGO_READY_TIMEOUT
    while time.time() < deadline:
        r = subprocess.run(
            ["docker", "exec", _MONGO_CONTAINER,
             "mongo", "--quiet", "--eval", "db.adminCommand('ping').ok"],
            capture_output=True, timeout=5
        )
        if r.returncode == 0 and b"1" in r.stdout:
            return
        time.sleep(2)
    raise RuntimeError(f"MongoDB container did not become healthy within {_MONGO_READY_TIMEOUT}s")


def _rita_run(args: list[str], cfg_path: str) -> subprocess.CompletedProcess:
    """Run a RITA command via docker run on the rita_net network."""
    return subprocess.run(
        [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "--network", _RITA_NETWORK,
            "-v", f"{cfg_path}:/etc/rita/config.yaml:ro",
        ] + args + [
            _RITA_IMAGE,
        ],
        capture_output=True, text=True, timeout=300
    )


def _rita_import(zeek_log_dir: str, db_name: str, cfg_path: str) -> None:
    """Import Zeek conn.log directory into RITA.

    Note: --delete flag fails when the database doesn't exist yet, so we
    first try a clean import; on second call (same analysis_name), existing
    data is silently merged by RITA (log files are deduped by content hash).
    """
    print(f"  [RITA] Importing Zeek logs → database '{db_name}'...")
    r = subprocess.run(
        [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "--network", _RITA_NETWORK,
            "-v", f"{cfg_path}:/etc/rita/config.yaml:ro",
            "-v", f"{zeek_log_dir}:/zeek_logs:ro",
            _RITA_IMAGE,
            "import", "/zeek_logs", db_name,
        ],
        capture_output=True, text=True, timeout=300
    )
    if r.returncode != 0:
        raise RuntimeError(f"RITA import failed: {r.stderr[:200]}")


def _rita_show_beacons(db_name: str, cfg_path: str) -> list[BeaconEntry]:
    """Query RITA show-beacons and parse CSV output.
    RITA exits 255 when no results exist — that is valid, not an error.
    """
    print(f"  [RITA] Querying beacons for '{db_name}'...")
    r = subprocess.run(
        [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "--network", _RITA_NETWORK,
            "-v", f"{cfg_path}:/etc/rita/config.yaml:ro",
            _RITA_IMAGE,
            "show-beacons", "--delimiter", ",", db_name,
        ],
        capture_output=True, text=True, timeout=60
    )
    combined = (r.stdout + r.stderr).strip()
    if r.returncode != 0 and not combined.startswith("No results"):
        raise RuntimeError(f"RITA show-beacons failed: {combined[:200]}")

    return _parse_beacons_csv(combined)


def _rita_delete_db(db_name: str, cfg_path: str) -> None:
    """Remove the RITA database to free MongoDB space."""
    subprocess.run(
        [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "--network", _RITA_NETWORK,
            "-v", f"{cfg_path}:/etc/rita/config.yaml:ro",
            _RITA_IMAGE,
            "delete", db_name,
        ],
        capture_output=True, text=True, timeout=30
    )


def _parse_beacons_csv(raw: str) -> list[BeaconEntry]:
    """
    Parse RITA show-beacons CSV.
    Expected header (RITA 4.x):
      Score,Source IP,Destination IP,Connections,Avg. Bytes,Intvl Range,
      Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,
      Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
    Returns empty list when RITA outputs "No results were found" or empty.
    """
    beacons: list[BeaconEntry] = []
    lines = [l for l in raw.strip().splitlines() if l.strip()]
    if not lines or lines[0].startswith("No results"):
        return beacons

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        try:
            beacons.append(BeaconEntry(
                score=float(row.get("Score", 0)),
                src_ip=row.get("Source IP", "").strip(),
                dst_ip=row.get("Destination IP", "").strip(),
                connections=int(row.get("Connections", 0)),
                avg_bytes=float(row.get("Avg. Bytes", 0)),
                top_interval_secs=float(row.get("Top Intvl", 0)),
                interval_skew=float(row.get("Intvl Skew", 0)),
                size_skew=float(row.get("Size Skew", 0)),
            ))
        except (ValueError, KeyError):
            continue

    beacons.sort(key=lambda b: b.score, reverse=True)
    return beacons
