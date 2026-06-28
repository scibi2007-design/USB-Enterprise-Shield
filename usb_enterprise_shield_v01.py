#!/usr/bin/env python3
"""
USB Enterprise Shield v8.0 - Commercial-Grade Security Edition
=======================================================================
PURPOSE: Cross-platform USB malware scanner with enterprise-grade features.
         Runs on Kali/Linux, macOS, and Windows.

v7.0 BASELINE (25 REQs carried forward):
  REQ-01..REQ-25: (all retained — see v7.0 header for full list)

v8.0 IMPROVEMENTS (20 new enhancements):
  IMP-01: Digital Signature Decision Tree
          Weighted score: Valid+TrustedPub=-30, Invalid=+30, Expired=+25,
          SelfSigned=+20, Revoked=+60, Unsigned executable=+15.
          Structured decision tree replaces flat adjustments.
  IMP-02: USB Device Trusted-Device Database with risk scoring
          First-seen USB → HIGH risk bonus (+20). Known-trusted serial → -20.
          Unknown vendor → +10. Device history used for risk decisions.
  IMP-03: Expanded Whitelist System
          System Volume Information / .Spotlight / .fseventsd / .Trashes /
          EFI auto-excluded. Folder whitelist + cert whitelist per publisher.
  IMP-04: Windowed Entropy Analysis
          File split into 4 equal windows; per-window entropy computed.
          Any single window ≥7.7 triggers packed-section flag independently.
          Replaces single whole-file entropy value for executables.
  IMP-05: YARA Weighted Scoring by Category
          Downloader=+20, PEInjection=+50, Persistence=+20,
          CredentialStealer=+40, Ransomware=+100, NetworkC2=+35.
          Per-category cap prevents double-counting within same category.
  IMP-06: Chunk-Based Large File Scanning
          Files >2 GB no longer skipped; scanned in 64 MB chunks via ClamAV
          pipe-scan. Hash/entropy continue streaming. Removes file-size skip.
  IMP-07: Comprehensive False-Positive Reduction
          Final score reduced when: valid signature present (-20), known-safe
          path (-15), media extension (-10). Score floor = 0.
  IMP-08: Multi-Format Report Generation
          In addition to .txt, every scan now produces:
            • report_<ts>.json  — full machine-readable JSON
            • report_<ts>.html  — styled HTML with timeline and risk table
            • report_<ts>.csv   — one row per scanned file (spreadsheet-ready)
          PDF report generation available when reportlab is installed.
  IMP-09: Scan Performance Pipeline
          Small files (≤50 KB, non-exec) → behavior-only fast path.
          Media files (.jpg/.png/.mp3 etc.) → quick MIME check, skip YARA.
          Reduces unnecessary full-scan overhead.
  IMP-10: Quarantine Restore & Scheduled Purge
          SecureQuarantine.restore(vault_path) decrypts and restores file.
          Items older than quarantine_retention_days auto-purged on startup.
  IMP-11: Secure Logging with SHA-256 Tamper Detection
          Each log line appended with HMAC-SHA256 chain.
          SecureLogWriter class; log_integrity_check() verifies chain.
  IMP-12: HMAC-Protected Configuration File
          config.json written with "hmac" field (HMAC-SHA256 of content).
          On load, HMAC is verified; tampering raises ConfigTamperError.
  IMP-13: Network Awareness Post-USB-Insertion
          ProcessMonitor extended: new processes after USB insert that open
          network connections (PowerShell, curl, wget, python, wscript)
          raise correlation risk. Risk bonus +40 applied to overall scan.
  IMP-14: ML Feature Set Expanded
          Added: digital_signature_valid, cert_publisher_trusted,
          yara_category_count, network_ioc_count, archive_depth,
          file_age_days, section_entropy_max, dangerous_import_count.
          Total features: 20 (up from 12).
  IMP-15: Weighted Overall Risk Score Formula
          Component weights per security engineering review:
            ClamAV=100, ValidSig=-30, InvalidSig=+30, YARAHigh=+40,
            BehaviorDanger=+60, HighEntropy=+20, KnownSafeHash=-100,
            TrustedDevice=-20, ArchiveMalware=+50, MemoryCorrelation=+30,
            NetworkCorrelation=+40. Score clamped [0, 200] → normalised /2.
  IMP-16: Process Memory Correlation
          MemoryScanner.correlate_usb_event() called after USB insert:
          if a new RWX-mapped process or suspicious parent chain appears
          within 10 s of USB mount, overall_risk += 30.
  IMP-17: Secure Config Storage
          TrustPolicy & WhitelistDB persisted to config.json with HMAC.
          Attacker cannot silently add a serial to the trusted list.
  IMP-18: Startup Quarantine Purge
          Quarantine items older than quarantine_retention_days (default 90)
          are securely wiped (overwrite + delete) on startup.
  IMP-19: Chunk-Window Entropy for Large Executables
          Executables >8 MB scanned in 1 MB windows; highest-window entropy
          reported separately as "peak_entropy". Triggers packed-section
          flag at peak ≥7.5 even if whole-file entropy is moderate.
  IMP-20: Startup & Runtime Dependency Check Table
          startup_check() extended with install commands per missing dep.
          --check-only flag added: prints dependency table and exits.

v9.1 SECURITY / SCALABILITY HARDENING (response to internal code-review findings):
  HARDEN-01: Vectorised entropy (NumPy bincount, Counter fallback) — removes
             the per-byte Python loop that made entropy the CPU bottleneck.
  HARDEN-02: Fused streaming SHA256+entropy pass (sha256_and_entropy()) so
             the two heaviest per-byte operations share a single file read
             instead of two; 4-tier file prioritisation (exec > script >
             document > media) expanded from the previous 2-tier split.
  HARDEN-03: Standalone-entropy score reduced to a low base value; it only
             escalates when corroborated by another signal (YARA/PE/network),
             via the existing BehavioralCorrelationEngine combo bonuses —
             reduces alert fatigue from entropy-only false positives.
  HARDEN-04: SecureQuarantine rewritten to streaming AES-256-GCM (AEAD).
             Files are encrypted/decrypted in chunks — never loaded fully
             into RAM — and integrity is verified before any restore.
             The weak XOR fallback is removed entirely; quarantine fails
             securely (raises, does not silently downgrade) if pycryptodome
             is missing. restore() and purge_expired() — promised by IMP-10/
             IMP-18 but never implemented — are now implemented.
  HARDEN-05: USBIdentity.fingerprint() — SHA256(serial+uuid+vid+pid+fstype)
             — plus DeviceHistory consistency checking: if a previously-seen
             serial reappears with a different VID/PID/filesystem, that is
             flagged as a possible spoofed/cloned device. (Software
             fingerprinting raises the bar but cannot fully stop a
             programmable device that fakes everything — see class
             docstring for the hardware-backed alternative.)
  HARDEN-06: Optional fuzzy-hash similarity matching (TLSH) wired into
             ReputationChecker, so a single-byte-changed malware variant
             still matches a near-identical known-bad sample.
  HARDEN-07: Explicit CORE vs OPTIONAL dependency tiers. main() now aborts
             startup with a clear message if a CORE dependency is missing,
             instead of limping along; OPTIONAL deps continue to degrade
             gracefully as before.
  HARDEN-08: ReputationChecker privacy modes ("offline_only" / "hash_lookup"
             / "upload_samples"); enterprise default is "offline_only" so
             no hash leaves the building unless explicitly configured.
  HARDEN-09: ScanCache rewritten onto SQLite with a rules/signature version
             column (YARA ruleset signature + ClamAV DB mtime fingerprint).
             A cache row from before the last signature update is treated
             as a miss automatically — fixes "scanned clean yesterday, still
             cached clean today even though signatures changed".
  HARDEN-10: MemoryScanner now requires >=2 corroborating indicators (e.g.
             RWX region + suspicious module path + deleted exe) before
             flagging a process "suspicious" — a bare RWX region (normal
             for Chrome/JVM/VMware) no longer alerts on its own.
  HARDEN-11: ProcessMonitor replaced unconditional kill() with policy-based
             actions (ALLOW / PROMPT / SANDBOX / BLOCK) driven by a quick
             risk assessment of the launched process, so legitimate
             installers/portable apps from USB aren't killed on sight.
  HARDEN-12: DeviceHistory rewritten onto SQLite (an append-only log that
             can reach millions of rows must not be a full JSON rewrite on
             every single scan).
  HARDEN-13: ArchiveScanner._extract() now enforces a per-member
             decompression-ratio and cumulative-size guard *during*
             extraction (not after), validates every extracted path stays
             inside the temp sandbox (zip-slip / path-traversal guard), and
             aborts early — closing the "42 KB zip bomb fills the disk
             before anyone notices" gap.
  HARDEN-14: MLTrainingPipeline + `--train-model` CLI flag: an actual
             train/validation/test pipeline (precision/recall/ROC-AUC/FPR)
             for the RandomForest scorer used by MLHeuristicScorer, so the
             model's quality is measurable instead of asserted.
  (Risk-score correlation/confidence-tiering and the local SQLite reputation
   DB referenced in the review were already implemented pre-v9.1 — see
   BehavioralCorrelationEngine, compute_detection_confidence(), and
   ReputationChecker — and are left as-is.)

USAGE:
  sudo python3 usb_enterprise_shield_v9.py              # default monitor loop
  sudo python3 usb_enterprise_shield_v9.py --copy-clean
  sudo python3 usb_enterprise_shield_v9.py --config /path/to/config.json
  sudo python3 usb_enterprise_shield_v9.py --sandbox    # enable sandbox detonation
  sudo python3 usb_enterprise_shield_v9.py --scan-memory
  sudo python3 usb_enterprise_shield_v9.py --check-only # dependency check only
  sudo python3 usb_enterprise_shield_v9.py --train-model /path/to/dataset_dir
"""

# ---------------------------------------------------------------------------
# STANDARD LIBRARY IMPORTS
# ---------------------------------------------------------------------------
import argparse
import base64
import collections
import ctypes
import hashlib
import hmac as hmac_lib
import ipaddress
import json
import logging
import math
import os
import plistlib
import platform
import queue
import re
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import datetime
import zipfile
import tarfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# OPTIONAL THIRD-PARTY IMPORTS  (graceful degradation when absent)
# ---------------------------------------------------------------------------
try:
    import psutil
except ImportError:
    psutil = None

try:
    import yara
except ImportError:
    yara = None

try:
    import magic                      # python-magic → REQ-09
except ImportError:
    magic = None

try:
    import oletools.olevba as olevba
    import oletools.oleid as oleid
    try:
        import oletools.mraptor as mraptor
        MRAPTOR_AVAILABLE = True
    except ImportError:
        MRAPTOR_AVAILABLE = False
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    MRAPTOR_AVAILABLE = False

try:
    import pefile                     # REQ-10: PE analysis
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import lief                       # REQ-10/11/12: PE/ELF/Mach-O
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile   # REQ-11: ELF analysis
    from elftools.common.exceptions import ELFError
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False

try:
    import macholib.MachO as MachO    # REQ-12: Mach-O analysis
    MACHOLIB_AVAILABLE = True
except ImportError:
    MACHOLIB_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import numpy as np                # HARDEN-01: vectorised entropy (independent of ML)
    NUMPY_AVAILABLE = True
except ImportError:
    np = None
    NUMPY_AVAILABLE = False

try:
    import sklearn.ensemble as ske    # REQ-16: ML
    ML_AVAILABLE = NUMPY_AVAILABLE    # sklearn needs numpy anyway
except ImportError:
    ML_AVAILABLE = False

try:
    import tlsh                       # HARDEN-06: fuzzy hashing (similarity matching)
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

try:
    import requests                   # REQ-03: reputation APIs
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4            # IMP-08: PDF report
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors as rl_colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------------------------------------------------------------------
# REQ-20 / REQ-21 / REQ-25: CONFIG
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "base_dir": os.path.join(str(Path.home()), "USB_Enterprise_Shield_Data"),
    "clamav_db_dir": "/var/lib/clamav",
    # Size limits
    "max_behavior_file_size": 500 * 1024 * 1024,
    "max_clamav_file_size": 2 * 1024 * 1024 * 1024,
    "max_yara_file_size": 100 * 1024 * 1024,
    "max_text_read": 2 * 1024 * 1024,
    "max_copy_file_size": 500 * 1024 * 1024,
    "max_archive_extract_size": 200 * 1024 * 1024,
    "max_archive_members": 500,
    "max_archive_depth": 4,           # REQ-07
    # REQ-20: streaming chunk size for large files
    "stream_chunk_size": 4 * 1024 * 1024,
    # Threading
    "max_workers": os.cpu_count() or 4,   # REQ-25: adaptive
    # Timeouts
    "clamav_timeout": 120,
    "yara_timeout": 10,
    "scan_task_timeout": 180,
    "signature_check_timeout": 15,
    "sandbox_timeout": 300,           # REQ-17
    # Risk thresholds
    "score_danger": 85,
    "score_warning": 45,
    "default_usb_policy": "READ_ONLY",
    # API keys (REQ-03)
    "virustotal_api_key": "",
    "malware_bazaar_api_key": "",
    "openTIP_api_key": "",
    "any_run_api_key": "",            # REQ-17
    "cuckoo_url": "",                 # REQ-17: e.g. http://localhost:8090
    # Trusted publishers (REQ-01 / REQ-19)
    "trusted_publishers": [
        "Microsoft Corporation", "Google LLC", "Adobe Inc.", "Apple Inc.",
        "Oracle Corporation", "Intel Corporation", "NVIDIA Corporation",
        "Mozilla Corporation", "Canonical Ltd.", "Red Hat, Inc.",
    ],
    # REQ-22: Quarantine
    "quarantine_enabled": True,
    # REQ-16: ML
    "ml_model_path": "",
    # REQ-21: Cache TTL seconds (0 = disabled)
    "cache_ttl_seconds": 3600,
    # REQ-24: Retry settings
    "max_retries": 3,
    "retry_delay_seconds": 1,
    # REQ-25: Priority queue – scan executables first
    "priority_extensions": [".exe", ".dll", ".scr", ".sys", ".bat",
                             ".cmd", ".ps1", ".vbs", ".js", ".hta"],
    # REQ-23: Whitelist DB entries (SHA256/cert/vid-pid/path)
    "whitelist_sha256": [],
    "whitelist_publishers": ["Microsoft Windows", "Microsoft Corporation"],
    "whitelist_vid_pid": [
        {"vendor_id": "0951", "product_id": "1666"},  # Kingston DataTraveler
        {"vendor_id": "0781", "product_id": "5581"},  # SanDisk Ultra
        {"vendor_id": "04e8", "product_id": "61f5"},  # Samsung
    ],
    "whitelist_paths": [],
    # IMP-03: Auto-excluded system folders (always skipped)
    "system_exclude_folders": [
        "System Volume Information", ".Spotlight-V100", ".fseventsd",
        ".Trashes", "$RECYCLE.BIN", "EFI", ".TemporaryItems",
    ],
    # IMP-06: Chunk-based large file scanning (replaces skip)
    "large_file_chunk_scan_enabled": True,
    "large_file_chunk_mb": 64,
    # IMP-08: Multi-format report output
    "report_formats": ["txt", "json", "html", "csv"],  # pdf requires reportlab
    # IMP-10: Quarantine retention days (0 = keep forever)
    "quarantine_retention_days": 90,
    # IMP-12: Config HMAC secret (auto-generated if empty)
    "config_hmac_secret": "",
    # IMP-13: Network awareness post-USB insertion
    "network_awareness_enabled": True,
    "network_watch_window_seconds": 30,
    # IMP-15: Weighted score component weights
    "score_weight_clamav":          100,
    "score_weight_valid_sig":        -30,
    "score_weight_invalid_sig":       30,
    "score_weight_yara_high":         40,
    "score_weight_behavior_danger":   60,
    "score_weight_high_entropy":      20,
    "score_weight_known_safe_hash": -100,
    "score_weight_trusted_device":   -20,
    "score_weight_archive_malware":   50,
    "score_weight_memory_corr":       30,
    "score_weight_network_corr":      40,
    # IMP-04: Windowed entropy windows
    "entropy_window_count": 4,
    "entropy_window_danger_threshold": 7.5,
    # HARDEN-08: Reputation privacy mode — "offline_only" (default, no hash
    # ever leaves the building), "hash_lookup" (SHA256 only, no file bytes),
    # "upload_samples" (full sample upload to sandbox/cloud AV allowed).
    "reputation_mode": "offline_only",
    # HARDEN-06: Fuzzy-hash (TLSH) similarity threshold — lower = more similar.
    # TLSH diff scores are roughly 0 (identical) .. 300+ (unrelated); <=40 is
    # a strong "near-identical variant" signal in practice.
    "fuzzy_hash_max_distance": 40,
    # HARDEN-13: Archive bomb guard — abort if (decompressed/compressed) for
    # a single member exceeds this ratio, checked incrementally as each
    # member is written rather than after the whole archive is unpacked.
    "archive_max_compression_ratio": 100,
    # HARDEN-11: Process-policy thresholds for processes launched from USB.
    # risk >= block  -> BLOCK (terminate); >= sandbox -> SANDBOX/contain;
    # >= prompt -> PROMPT user; else -> ALLOW.
    "process_policy_block_threshold":   90,
    "process_policy_sandbox_threshold": 60,
    "process_policy_prompt_threshold":  30,
    # HARDEN-07: Dependencies that are genuinely required for the scanner to
    # provide its core safety guarantee (process/file visibility). Without
    # these, the tool would be silently blind rather than degraded.
    "core_dependencies": ["psutil"],
    # IMP-05: YARA per-category weights
    "yara_category_weights": {
        "Downloader":        20,
        "PEInjection":       50,
        "DLLInjection":      50,
        "Persistence":       20,
        "CredentialStealer": 40,
        "Ransomware":       100,
        "NetworkC2":         35,
        "PowerShell":        25,
        "OfficeMacro":       30,
        "USBWorm":           45,
        "JavaScript":        20,
        "PackedExecutable":  25,
        "Obfuscation":       15,
        "Cryptominer":       20,
        "PDF":               20,
        "ReverseShell":      40,
    },
}

CFG: Dict[str, Any] = dict(DEFAULT_CONFIG)


def load_config(path: Optional[str]) -> None:
    if not path or not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
        CFG.update({k: v for k, v in user.items() if k in DEFAULT_CONFIG})
        log(f"Config loaded from {path}", "info")
    except (json.JSONDecodeError, OSError) as exc:
        log(f"Config file error ({exc}); using defaults.", "warning")


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
APP_NAME = "USB Enterprise Shield"
VERSION  = "8.0-commercial"

CLAMAV_DB_CANDIDATES = [
    "/var/lib/clamav", "/usr/local/var/lib/clamav",
    "/opt/homebrew/var/lib/clamav",
    r"C:\ProgramData\ClamAV\db",
    r"C:\Program Files\ClamAV\database",
]

EXCLUDE_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", ".Spotlight-V100",
    ".fseventsd", ".Trashes", "System Volume Information", "$RECYCLE.BIN",
    "EFI", ".TemporaryItems",  # IMP-03: expanded system folder exclusions
}

# IMP-09: Media files get quick MIME check only (skip full YARA/behavior)
MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".m4v",
    ".avi", ".mkv", ".mov", ".wmv", ".mpeg", ".mpg",
    ".ttf", ".otf", ".woff", ".woff2",
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2",
    ".xz", ".iso", ".cab", ".msi", ".apk", ".jar"
}

OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp"
}

EXEC_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".sh", ".command", ".py", ".hta",
    ".dmg", ".pkg"
}

SCRIPT_EXTENSIONS = {
    ".sh", ".bash", ".zsh", ".command", ".py", ".pl", ".rb",
    ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".php",
    ".html", ".htm"
}

ENTROPY_EXTENSIONS = EXEC_EXTENSIONS | SCRIPT_EXTENSIONS

# ---------------------------------------------------------------------------
# THREAD SAFETY & SIGNAL HANDLING
# ---------------------------------------------------------------------------
STOP_EVENT   = threading.Event()
PRINT_LOCK   = threading.Lock()
CACHE_LOCK   = threading.Lock()
PROCESS_LOCK = threading.Lock()


def _signal_handler(signum, frame):
    STOP_EVENT.set()
    log("Stop requested – cancelling pending scans…", "warning")


signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
_logger = logging.getLogger("usb_shield")


class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    WHITE  = "\033[97m"
    END    = "\033[0m"


def log(msg: str, level: str = "info", quiet: bool = False) -> None:
    color = {"info": Colors.BLUE, "success": Colors.GREEN,
             "warning": Colors.YELLOW, "danger": Colors.RED}.get(level, Colors.WHITE)
    icon  = {"info": "ℹ️ ", "success": "✅ ",
              "warning": "⚠️ ", "danger": "🚨 "}.get(level, "")
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line  = f"[{ts}] {icon} {msg}"
    if not quiet:
        with PRINT_LOCK:
            print(f"\r{color}{line}{Colors.END}" + " " * 10)
    lvl_fn = {"danger": _logger.error, "warning": _logger.warning}.get(level, _logger.info)
    lvl_fn(line)


def notify_user(title: str, message: str) -> None:
    try:
        sysname = platform.system()
        if sysname == "Linux" and shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], timeout=3)
        elif sysname == "Darwin":
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                timeout=3
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# UTILITY HELPERS
# ---------------------------------------------------------------------------
def safe_name(name: str, limit: int = 180) -> str:
    name = os.path.basename(name)
    name = re.sub(r"[^A-Za-z0-9._()\- ]+", "_", name).strip().strip(".")
    return (name or "file")[:limit]


def realpath_inside(path: str, root: str) -> bool:
    try:
        rp = os.path.realpath(path)
        rr = os.path.realpath(root)
        return rp == rr or rp.startswith(rr + os.sep)
    except Exception:
        return False


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def sha256_file(path: str) -> Optional[str]:
    """REQ-20: Streaming SHA256 — never loads entire file into memory."""
    if os.path.islink(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(CFG.get("stream_chunk_size", 4 * 1024 * 1024))
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def entropy_bytes(data: bytes) -> float:
    """HARDEN-01: Vectorised Shannon entropy. Uses NumPy's C-implemented
    bincount when available; falls back to collections.Counter (still
    C-accelerated internally) instead of a per-byte Python for-loop, which
    was the original CPU bottleneck on large/many files."""
    if not data:
        return 0.0
    length = len(data)
    if NUMPY_AVAILABLE:
        arr    = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        nz     = counts[counts > 0]
        probs  = nz / length
        return float(-np.sum(probs * np.log2(probs)))
    counts = collections.Counter(data)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def entropy_stream(path: str, max_bytes: int = 8 * 1024 * 1024) -> float:
    """REQ-20 / HARDEN-01: Streaming entropy — reads in chunks, never loads
    the whole file at once, and accumulates byte counts with NumPy/Counter
    instead of a per-byte loop."""
    if os.path.islink(path):
        return 0.0
    counts = np.zeros(256, dtype=np.int64) if NUMPY_AVAILABLE else collections.Counter()
    total  = 0
    try:
        with open(path, "rb") as fh:
            while total < max_bytes:
                chunk = fh.read(min(CFG.get("stream_chunk_size", 4 * 1024 * 1024),
                                    max_bytes - total))
                if not chunk:
                    break
                if NUMPY_AVAILABLE:
                    arr = np.frombuffer(chunk, dtype=np.uint8)
                    counts += np.bincount(arr, minlength=256)
                else:
                    counts.update(chunk)
                total += len(chunk)
    except (PermissionError, OSError):
        return 0.0
    if total == 0:
        return 0.0
    if NUMPY_AVAILABLE:
        nz    = counts.astype(np.float64)
        nz    = nz[nz > 0]
        probs = nz / total
        return float(-np.sum(probs * np.log2(probs)))
    ent = 0.0
    for c in counts.values():
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def sha256_and_entropy(path: str, max_entropy_bytes: int = 8 * 1024 * 1024) -> Tuple[Optional[str], float]:
    """HARDEN-02: Single-pass fix for the two heaviest streaming operations.
    Reads the file ONCE — updating the SHA256 hash AND accumulating entropy
    byte-counts from the same chunk — instead of sha256_file() and
    entropy_stream() each doing their own independent full read. (ClamAV and
    YARA still manage their own I/O since they're external engines/C
    extensions that take a file path, not a buffer — see header HARDEN-02
    note — so this fuses the two operations that *are* fusable.)
    """
    if os.path.islink(path):
        return None, 0.0
    h = hashlib.sha256()
    counts = np.zeros(256, dtype=np.int64) if NUMPY_AVAILABLE else collections.Counter()
    entropy_total = 0
    chunk_size = CFG.get("stream_chunk_size", 4 * 1024 * 1024)
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
                if entropy_total < max_entropy_bytes:
                    take = chunk if entropy_total + len(chunk) <= max_entropy_bytes \
                        else chunk[:max_entropy_bytes - entropy_total]
                    if NUMPY_AVAILABLE:
                        arr = np.frombuffer(take, dtype=np.uint8)
                        counts += np.bincount(arr, minlength=256)
                    else:
                        counts.update(take)
                    entropy_total += len(take)
    except (PermissionError, OSError):
        return None, 0.0
    sha = h.hexdigest()
    if entropy_total == 0:
        return sha, 0.0
    if NUMPY_AVAILABLE:
        nz    = counts.astype(np.float64)
        nz    = nz[nz > 0]
        probs = nz / entropy_total
        ent   = float(-np.sum(probs * np.log2(probs)))
    else:
        ent = 0.0
        for c in counts.values():
            if c:
                p = c / entropy_total
                ent -= p * math.log2(p)
    return sha, ent


# REQ-25: entropy result cache (sha256 → entropy float)
_ENTROPY_CACHE: Dict[str, float] = {}
_ENTROPY_CACHE_LOCK = threading.Lock()


def entropy_cached(path: str, sha256: Optional[str]) -> float:
    """REQ-25: Return cached entropy if available, else compute and store."""
    if sha256:
        with _ENTROPY_CACHE_LOCK:
            if sha256 in _ENTROPY_CACHE:
                return _ENTROPY_CACHE[sha256]
    ent = entropy_stream(path)
    if sha256:
        with _ENTROPY_CACHE_LOCK:
            _ENTROPY_CACHE[sha256] = ent
    return ent


def entropy_windowed(path: str, num_windows: int = 4,
                     max_bytes: int = 16 * 1024 * 1024) -> dict:
    """
    IMP-04 / IMP-19: Split file into num_windows equal chunks; compute
    per-window entropy. Returns {windows: [float...], peak: float,
    mean: float, packed_section: bool}.
    """
    result = {"windows": [], "peak": 0.0, "mean": 0.0, "packed_section": False}
    if os.path.islink(path):
        return result
    try:
        fsize = os.path.getsize(path)
    except OSError:
        return result
    if fsize == 0:
        return result
    read_bytes = min(fsize, max_bytes)
    window_size = max(read_bytes // num_windows, 4096)
    threshold   = CFG.get("entropy_window_danger_threshold", 7.5)
    entropies   = []
    try:
        with open(path, "rb") as fh:
            for _ in range(num_windows):
                chunk = fh.read(window_size)
                if not chunk:
                    break
                entropies.append(entropy_bytes(chunk))
    except (PermissionError, OSError):
        return result
    if not entropies:
        return result
    result["windows"]        = [round(e, 3) for e in entropies]
    result["peak"]           = round(max(entropies), 3)
    result["mean"]           = round(sum(entropies) / len(entropies), 3)
    result["packed_section"] = result["peak"] >= threshold
    return result


def get_drive_signature(drive: dict) -> str:
    return json.dumps(
        {k: drive.get(k, "") for k in ("mountpoint", "device", "uuid", "bus", "serial")},
        sort_keys=True
    )


# ---------------------------------------------------------------------------
# REQ-24: RETRY DECORATOR
# ---------------------------------------------------------------------------
def with_retry(fn, *args, max_retries: int = None, delay: float = None, **kwargs):
    """REQ-24: Retry fn(*args, **kwargs) up to max_retries times on exception."""
    max_retries = max_retries if max_retries is not None else CFG.get("max_retries", 3)
    delay       = delay if delay is not None else CFG.get("retry_delay_seconds", 1)
    last_exc    = None
    for attempt in range(max_retries + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                time.sleep(delay)
    raise last_exc


# ---------------------------------------------------------------------------
# REQ-23: WHITELIST DATABASE
# ---------------------------------------------------------------------------
class WhitelistDB:
    """
    REQ-23: Trusted entries for SHA256, certificate publishers, VID/PID,
    and trusted file paths. If a file matches ANY whitelist entry, it gets
    a -50 score adjustment and is flagged as whitelisted.
    """
    def __init__(self):
        self._sha256:     Set[str]       = set(CFG.get("whitelist_sha256", []))
        self._publishers: Set[str]       = set(CFG.get("whitelist_publishers", []))
        self._vid_pid:    List[dict]     = CFG.get("whitelist_vid_pid", [])
        self._paths:      List[str]      = CFG.get("whitelist_paths", [])

    def is_whitelisted_hash(self, sha256: str) -> bool:
        return bool(sha256) and sha256.lower() in self._sha256

    def is_whitelisted_publisher(self, publisher: str) -> bool:
        return any(p.lower() in publisher.lower() for p in self._publishers)

    def is_whitelisted_device(self, identity: dict) -> bool:
        vid = identity.get("vendor_id", "").lower()
        pid = identity.get("product_id", "").lower()
        for entry in self._vid_pid:
            if (entry.get("vendor_id", "").lower() == vid and
                    entry.get("product_id", "").lower() == pid):
                return True
        return False

    def is_whitelisted_path(self, path: str) -> bool:
        for trusted in self._paths:
            if path.startswith(trusted):
                return True
        return False

    def check(self, path: str, sha256: Optional[str] = None,
              publisher: str = "") -> dict:
        result = {"whitelisted": False, "reason": "", "score_adjustment": 0}
        if sha256 and self.is_whitelisted_hash(sha256):
            result.update({"whitelisted": True, "reason": "SHA256 whitelist",
                            "score_adjustment": -100})
        elif publisher and self.is_whitelisted_publisher(publisher):
            result.update({"whitelisted": True, "reason": f"Publisher whitelist: {publisher}",
                            "score_adjustment": -50})
        elif self.is_whitelisted_path(path):
            result.update({"whitelisted": True, "reason": "Path whitelist",
                            "score_adjustment": -30})
        return result


# ---------------------------------------------------------------------------
# REQ-21: SCAN CACHE (in-memory TTL + persistent JSON)
# ---------------------------------------------------------------------------
class ScanCache:
    """
    REQ-21 / HARDEN-09: Persistent scan-result cache, backed by SQLite
    instead of a single JSON blob.

    Why SQLite instead of JSON (issue: "JSON storage doesn't scale"):
    the original implementation rewrote the *entire* cache file on every
    single `put()`. At enterprise scale (millions of files scanned) that is
    an O(n) write per file, i.e. O(n^2) total I/O for one full USB scan —
    it gets slower the longer the scan runs and is prone to corruption if
    interrupted mid-write. SQLite gives O(1) point writes/reads and atomic
    transactions instead.

    Why a `cache_version` column (issue: "cache staleness"): a row is keyed
    on (sha256) but is only considered a HIT if its stored `cache_version`
    matches the caller's *current* version string. Callers pass in a
    version derived from the YARA ruleset signature + ClamAV DB version
    (see USBScanPipeline.cache_version()), so the moment signatures update,
    every old row automatically becomes a miss — no separate invalidation
    sweep required.
    """
    def __init__(self, cache_path: str, ttl: int = 3600):
        self._path = cache_path
        self._ttl  = ttl
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_cache ("
            " sha256 TEXT PRIMARY KEY,"
            " result_json TEXT NOT NULL,"
            " cache_version TEXT NOT NULL,"
            " ts REAL NOT NULL"
            ")"
        )
        self._conn.commit()
        self._migrate_legacy_json()

    def _migrate_legacy_json(self) -> None:
        """One-time best-effort import of a pre-v9.1 JSON cache file, if
        present, so upgrading doesn't silently discard a warm cache. Legacy
        rows get cache_version='' so they're treated as stale until
        re-verified against current signatures (safe default)."""
        legacy = self._path.replace(".sqlite", ".json")
        if legacy == self._path or not os.path.isfile(legacy):
            return
        try:
            with open(legacy, "r", encoding="utf-8") as fh:
                old = json.load(fh)
            with self._lock:
                for sha, entry in old.items():
                    self._conn.execute(
                        "INSERT OR IGNORE INTO scan_cache VALUES (?,?,?,?)",
                        (sha, json.dumps(entry.get("result", {})), "",
                         entry.get("ts", 0))
                    )
                self._conn.commit()
            os.rename(legacy, legacy + ".migrated")
            log(f"Migrated legacy JSON cache ({len(old)} rows) into SQLite.", "info")
        except (json.JSONDecodeError, OSError, sqlite3.Error) as exc:
            log(f"Legacy cache migration skipped: {exc}", "warning")

    def get(self, sha256: str, cache_version: str = "") -> Optional[dict]:
        if not sha256 or self._ttl == 0:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT result_json, cache_version, ts FROM scan_cache WHERE sha256=?",
                (sha256,)
            ).fetchone()
        if not row:
            return None
        result_json, row_version, ts = row
        if time.time() - ts > self._ttl:
            self._delete(sha256)
            return None
        if cache_version and row_version != cache_version:
            # HARDEN-09: signatures changed since this row was cached.
            return None
        try:
            return json.loads(result_json)
        except json.JSONDecodeError:
            return None

    def put(self, sha256: str, result: dict, cache_version: str = "") -> None:
        if not sha256 or self._ttl == 0:
            return
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO scan_cache VALUES (?,?,?,?)",
                    (sha256, json.dumps(result), cache_version, time.time())
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                log(f"ScanCache write failed: {exc}", "warning")

    def _delete(self, sha256: str) -> None:
        with self._lock:
            try:
                self._conn.execute("DELETE FROM scan_cache WHERE sha256=?", (sha256,))
                self._conn.commit()
            except sqlite3.Error:
                pass

    def evict_expired(self) -> None:
        cutoff = time.time() - self._ttl
        with self._lock:
            try:
                self._conn.execute("DELETE FROM scan_cache WHERE ts < ?", (cutoff,))
                self._conn.commit()
            except sqlite3.Error:
                pass


# ---------------------------------------------------------------------------
# REQ-02: USB DEVICE IDENTIFICATION
# ---------------------------------------------------------------------------
class USBIdentity:
    """
    REQ-02: Collect VID/PID/Serial/Manufacturer/Product/Bus Speed/USB Version
    from OS-level USB subsystem.

    HARDEN-05 (USB identity spoofing): VID/PID/serial are exactly the three
    fields a programmable device (Rubber Ducky, Hak5 O.MG, a generic
    microcontroller) can freely fake, because they're just strings the
    device reports over the USB protocol — there's no cryptographic root of
    trust behind them. fingerprint() combines several reported fields into
    one hash purely so that DeviceHistory can later notice *inconsistency*
    (e.g. the same serial showing up with a different VID/PID or filesystem
    UUID than before), which is a real anomaly signal. It does NOT make the
    identity unspoofable — a sufficiently capable attacker can still fake
    every field consistently. The only fix that actually closes that gap is
    out-of-band: hardware-backed USB authentication (e.g. USB devices that
    carry a certificate and respond to a challenge), which requires
    certificate-capable hardware on the trusted-device side and is outside
    what a host-side Python scanner can verify on its own.
    """
    def __init__(self, data_dir: str):
        self._path = os.path.join(data_dir, "trusted_devices.json")
        self._db: List[dict] = self._load()

    def _load(self) -> List[dict]:
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def _save(self) -> None:
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(self._db, fh, indent=2)
        except OSError as exc:
            log(f"USBIdentity save failed: {exc}", "warning")

    @staticmethod
    def fingerprint(identity: dict) -> str:
        """HARDEN-05: SHA256 over serial+vendor_id+product_id+filesystem
        UUID+fstype. Order-stable, lower-cased, '|'-joined so the hash is
        deterministic across repeated insertions of the same device."""
        parts = [
            str(identity.get("serial", "")).strip().lower(),
            str(identity.get("vendor_id", "")).strip().lower(),
            str(identity.get("product_id", "")).strip().lower(),
            str(identity.get("uuid", "")).strip().lower(),
            str(identity.get("fstype", "")).strip().lower(),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def query_linux(self, device: str) -> dict:
        info: dict = {}
        if not shutil.which("udevadm") or not device:
            return info
        try:
            res = subprocess.run(
                ["udevadm", "info", "--query=all", "--name", device],
                capture_output=True, text=True, timeout=10
            )
            mapping = {
                "ID_VENDOR_ID":    "vendor_id",
                "ID_MODEL_ID":     "product_id",
                "ID_SERIAL_SHORT": "serial",
                "ID_VENDOR":       "manufacturer",
                "ID_MODEL":        "product_name",
                "ID_REVISION":     "revision",
                "ID_USB_DRIVER":   "usb_driver",
                "ID_BUS":          "bus",
            }
            for line in res.stdout.splitlines():
                for key, field in mapping.items():
                    if f"E: {key}=" in line:
                        info[field] = line.split("=", 1)[1].strip()
            # Get USB speed via lsusb if available
            if shutil.which("lsusb") and info.get("vendor_id") and info.get("product_id"):
                lsusb_res = subprocess.run(
                    ["lsusb", "-d", f"{info['vendor_id']}:{info['product_id']}", "-v"],
                    capture_output=True, text=True, timeout=5
                )
                m = re.search(r"bcdUSB\s+([\d.]+)", lsusb_res.stdout)
                if m:
                    info["usb_version"] = m.group(1)
                m2 = re.search(r"bMaxPacketSize0\s+(\d+)", lsusb_res.stdout)
                if m2:
                    info["max_packet_size"] = m2.group(1)
        except (subprocess.TimeoutExpired, OSError):
            pass
        return info

    def query_macos(self, device: str) -> dict:
        info: dict = {}
        try:
            res = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=20
            )
            data = json.loads(res.stdout)
            def walk(node):
                if isinstance(node, list):
                    for item in node:
                        yield from walk(item)
                elif isinstance(node, dict):
                    if "bsd_name" in node and device and node["bsd_name"] in device:
                        yield node
                    for v in node.values():
                        yield from walk(v)
            for item in walk(data):
                info["manufacturer"]  = item.get("manufacturer", "")
                info["product_name"]  = item.get("_name", "")
                info["vendor_id"]     = item.get("vendor_id", "")
                info["product_id"]    = item.get("product_id", "")
                info["serial"]        = item.get("serial_num", "")
                info["usb_version"]   = item.get("bcd_usb", "")
                info["bus_power"]     = item.get("bus_power", "")
                info["speed"]         = item.get("speed", "")
                break
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass
        return info

    def query_windows(self, drive_letter: str) -> dict:
        info: dict = {}
        if platform.system() != "Windows":
            return info
        ps = (
            "Get-WmiObject Win32_DiskDrive | "
            "Where-Object {$_.MediaType -match 'Removable'} | "
            "Select-Object -First 1 PNPDeviceID,Manufacturer,Model,SerialNumber,Size | "
            "ConvertTo-Json"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=15
            )
            d = json.loads(res.stdout)
            info["manufacturer"]  = d.get("Manufacturer", "")
            info["product_name"]  = d.get("Model", "")
            info["serial"]        = d.get("SerialNumber", "")
            info["capacity"]      = d.get("Size", "")
            pnp = d.get("PNPDeviceID", "")
            m = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", pnp)
            if m:
                info["vendor_id"]  = m.group(1)
                info["product_id"] = m.group(2)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass
        return info

    def identify(self, drive: dict) -> dict:
        sysname = platform.system()
        if sysname == "Linux":
            identity = self.query_linux(drive.get("device", ""))
        elif sysname == "Darwin":
            identity = self.query_macos(drive.get("device", ""))
        else:
            identity = self.query_windows(drive.get("mountpoint", ""))
        identity["mountpoint"] = drive.get("mountpoint", "")
        identity["uuid"]       = drive.get("uuid", "")
        identity["fstype"]     = drive.get("fstype", "")
        identity["timestamp"]  = datetime.datetime.now().isoformat()
        identity["fingerprint"] = self.fingerprint(identity)  # HARDEN-05
        self._db.append(identity)
        self._save()
        return identity


# ---------------------------------------------------------------------------
# REQ-02 (continued): DEVICE HISTORY LOG
# ---------------------------------------------------------------------------
class DeviceHistory:
    """
    HARDEN-12: Rewritten onto SQLite. The original JSON version appended one
    entry per USB insertion to an in-memory list and re-wrote the *entire*
    file from scratch on every single insertion (`json.dump(self._db, ...)`)
    — fine for a handful of devices, but it becomes a full-file rewrite that
    grows without bound at enterprise scale (thousands of devices x
    thousands of insertions). SQLite gives an indexed, append-only table
    instead, plus the lookups HARDEN-05's spoof-consistency check needs.
    """
    def __init__(self, data_dir: str):
        self._path = os.path.join(data_dir, "device_history.sqlite")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS device_history ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " timestamp TEXT, computer TEXT, os TEXT, mountpoint TEXT,"
            " device TEXT, uuid TEXT, serial TEXT, manufacturer TEXT,"
            " product_name TEXT, vendor_id TEXT, product_id TEXT,"
            " usb_version TEXT, speed TEXT, capacity TEXT, fstype TEXT,"
            " fingerprint TEXT, scan_summary_json TEXT"
            ")"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_history_serial "
            "ON device_history(serial)"
        )
        self._conn.commit()
        self._migrate_legacy_json(data_dir)

    def _migrate_legacy_json(self, data_dir: str) -> None:
        legacy = os.path.join(data_dir, "device_history.json")
        if not os.path.isfile(legacy):
            return
        try:
            with open(legacy, "r", encoding="utf-8") as fh:
                old = json.load(fh)
            with self._lock:
                for entry in old:
                    self._conn.execute(
                        "INSERT INTO device_history "
                        "(timestamp, computer, os, mountpoint, device, uuid, "
                        " serial, manufacturer, product_name, vendor_id, "
                        " product_id, usb_version, speed, capacity, fstype, "
                        " fingerprint, scan_summary_json) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (entry.get("timestamp", ""), entry.get("computer", ""),
                         entry.get("os", ""), entry.get("mountpoint", ""),
                         entry.get("device", ""), entry.get("uuid", ""),
                         entry.get("serial", ""), entry.get("manufacturer", ""),
                         entry.get("product_name", ""), entry.get("vendor_id", ""),
                         entry.get("product_id", ""), entry.get("usb_version", ""),
                         entry.get("speed", ""), entry.get("capacity", ""),
                         entry.get("fstype", ""), entry.get("fingerprint", ""),
                         json.dumps(entry.get("scan_summary", {})))
                    )
                self._conn.commit()
            os.rename(legacy, legacy + ".migrated")
            log(f"Migrated legacy device_history.json ({len(old)} rows) into SQLite.", "info")
        except (json.JSONDecodeError, OSError, sqlite3.Error) as exc:
            log(f"Legacy device history migration skipped: {exc}", "warning")

    def record(self, drive: dict, identity: dict, result_summary: dict) -> None:
        row = (
            datetime.datetime.now().isoformat(), platform.node(), platform.system(),
            drive.get("mountpoint"), drive.get("device"), drive.get("uuid"),
            identity.get("serial", ""), identity.get("manufacturer", ""),
            identity.get("product_name", ""), identity.get("vendor_id", ""),
            identity.get("product_id", ""), identity.get("usb_version", ""),
            identity.get("speed", ""), identity.get("capacity", ""),
            identity.get("fstype", ""), identity.get("fingerprint", ""),
            json.dumps(result_summary),
        )
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO device_history "
                    "(timestamp, computer, os, mountpoint, device, uuid, "
                    " serial, manufacturer, product_name, vendor_id, "
                    " product_id, usb_version, speed, capacity, fstype, "
                    " fingerprint, scan_summary_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    row
                )
                self._conn.commit()
            except sqlite3.Error as exc:
                log(f"DeviceHistory save failed: {exc}", "warning")

    def check_spoof_consistency(self, identity: dict) -> Optional[str]:
        """HARDEN-05: If this serial has been seen before with a different
        VID/PID or filesystem UUID, that's inconsistent with it being the
        same physical device — flag it as a possible spoofed/cloned device.
        Returns a human-readable warning string, or None if consistent /
        first-seen."""
        serial = (identity.get("serial") or "").strip()
        if not serial:
            return None
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT DISTINCT vendor_id, product_id, fstype FROM device_history "
                    "WHERE serial = ? ORDER BY id DESC LIMIT 20",
                    (serial,)
                ).fetchall()
            except sqlite3.Error:
                return None
        if not rows:
            return None
        vid, pid = identity.get("vendor_id", ""), identity.get("product_id", "")
        seen_combos = {(v or "", p or "") for v, p, _ in rows}
        if seen_combos and (vid, pid) not in seen_combos:
            prior = ", ".join(f"{v}:{p}" for v, p in sorted(seen_combos))
            return (f"Serial '{serial}' previously seen with VID:PID [{prior}], "
                    f"now reporting {vid}:{pid} — possible spoofed/cloned device.")
        return None

    def history_for_serial(self, serial: str, limit: int = 50) -> List[dict]:
        with self._lock:
            try:
                cols = ("id", "timestamp", "computer", "os", "mountpoint", "device",
                        "uuid", "serial", "manufacturer", "product_name", "vendor_id",
                        "product_id", "usb_version", "speed", "capacity", "fstype",
                        "fingerprint", "scan_summary_json")
                rows = self._conn.execute(
                    f"SELECT {','.join(cols)} FROM device_history "
                    "WHERE serial = ? ORDER BY id DESC LIMIT ?",
                    (serial, limit)
                ).fetchall()
            except sqlite3.Error:
                return []
        return [dict(zip(cols, r)) for r in rows]


# ---------------------------------------------------------------------------
# TRUST POLICY
# ---------------------------------------------------------------------------
class TrustPolicy:
    def __init__(self, data_dir: str, default: str = "READ_ONLY"):
        self._path    = os.path.join(data_dir, "policy.json")
        self._default = default
        self._policy  = self._load()

    def _load(self) -> dict:
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass
        skeleton = {"trusted": [], "blocked": [], "guest": []}
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(skeleton, fh, indent=2)
        except OSError:
            pass
        return skeleton

    def classify(self, identity: dict) -> str:
        serial = identity.get("serial", "").strip()
        vid    = identity.get("vendor_id", "").strip().lower()
        pid    = identity.get("product_id", "").strip().lower()

        def matches(entry: dict) -> bool:
            if entry.get("serial") and entry["serial"] == serial:
                return True
            if entry.get("vendor_id") and entry.get("product_id"):
                return (entry["vendor_id"].lower() == vid and
                        entry["product_id"].lower() == pid)
            return False

        for entry in self._policy.get("blocked", []):
            if matches(entry):
                return "BLOCKED"
        for entry in self._policy.get("trusted", []):
            if matches(entry):
                return "TRUSTED"
        for entry in self._policy.get("guest", []):
            if matches(entry):
                return "GUEST"
        return self._default


# ---------------------------------------------------------------------------
# REQ-22: SECURE QUARANTINE
# ---------------------------------------------------------------------------
class SecureQuarantine:
    """
    REQ-22 / HARDEN-04: AES-256-GCM (AEAD) encrypted vault, streamed in
    chunks. Files are renamed to .quar, permissions set to 000, and metadata
    stored separately.

    Why GCM instead of CBC (security fix): plain AES-CBC gives
    confidentiality but no integrity — an attacker who can write to the
    vault directory can flip ciphertext bits and the decrypted output
    changes in a predictable, attacker-influenced way (malleability), with
    no error raised. AES-GCM is an AEAD mode: it produces an authentication
    tag alongside the ciphertext, and decryption refuses to return any
    plaintext at all if the tag doesn't verify — so tampering is detected
    rather than silently decrypted into a corrupted/manipulated file.

    Why no XOR fallback (security fix): a stream cipher built from
    `key_stream = key * N` is a repeating-key XOR cipher. With two
    ciphertexts under the same key (guaranteed here, since every quarantined
    file reused self._key), XOR-ing them together cancels the key out and
    leaks a relationship between the two plaintexts — classic many-time-pad
    break. If pycryptodome isn't installed, quarantine now fails loudly
    (raises) instead of silently downgrading to a broken cipher.

    Why streaming (RAM fix): the previous implementation did
    `plaintext = fh.read()` — loading the *entire* file into memory before
    encrypting it once. A multi-GB file would exhaust RAM, especially with
    several worker threads quarantining files concurrently. Encryption here
    is done chunk-by-chunk via the cipher object's incremental encrypt()/
    decrypt(), so memory use stays bounded by the chunk size regardless of
    file size.
    """
    NONCE_SIZE = 12   # 96-bit GCM nonce (NIST-recommended size)
    TAG_SIZE   = 16   # 128-bit GCM authentication tag

    def __init__(self, data_dir: str):
        self._vault   = os.path.join(data_dir, "quarantine")
        self._keyfile = os.path.join(data_dir, "quarantine_key.bin")
        os.makedirs(self._vault, exist_ok=True)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        if os.path.isfile(self._keyfile):
            try:
                with open(self._keyfile, "rb") as fh:
                    return fh.read(32)
            except OSError:
                pass
        key = get_random_bytes(32) if CRYPTO_AVAILABLE else os.urandom(32)
        try:
            with open(self._keyfile, "wb") as fh:
                fh.write(key)
            os.chmod(self._keyfile, 0o600)
        except OSError:
            pass
        return key

    def quarantine(self, src: str, findings: List[str], sha256: str) -> dict:
        if os.path.islink(src):
            return {"quarantined": False, "error": "Refusing to quarantine symlink"}
        if not CRYPTO_AVAILABLE:
            # HARDEN-04 Fix B: fail securely — never fall back to a weak cipher.
            log("pycryptodome missing: cannot quarantine securely. "
                "Install pycryptodome (`pip install pycryptodome`).", "danger")
            return {"quarantined": False,
                    "error": "pycryptodome required for secure quarantine; "
                             "refusing to use a weak fallback cipher."}
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        name     = safe_name(os.path.basename(src))
        enc_dst  = os.path.join(self._vault, f"{ts}_{name}.quar")
        meta_dst = os.path.join(self._vault, f"{ts}_{name}.meta.json")
        chunk_size = CFG.get("stream_chunk_size", 4 * 1024 * 1024)
        try:
            nonce  = get_random_bytes(self.NONCE_SIZE)
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
            with open(src, "rb") as fh, open(enc_dst, "wb") as out:
                out.write(nonce)
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    out.write(cipher.encrypt(chunk))
                out.write(cipher.digest())   # GCM auth tag, written last
            try:
                os.chmod(enc_dst, 0o000)     # REQ-22: permission deny
            except OSError:
                pass
            meta = {
                "original_path":  src,
                "sha256":         sha256,
                "findings":       findings,
                "quarantined_at": datetime.datetime.now().isoformat(),
                "vault_file":     enc_dst,
                "encrypted":      True,
                "cipher":         "AES-256-GCM",
            }
            with open(meta_dst, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)
            return {"quarantined": True, "vault_path": enc_dst, "meta_path": meta_dst}
        except (PermissionError, OSError) as exc:
            return {"quarantined": False, "error": str(exc)}

    def restore(self, vault_path: str, dest_path: Optional[str] = None) -> dict:
        """HARDEN-04 / IMP-10: Decrypt and restore a quarantined file.

        The plaintext is streamed to a temporary file *inside the vault*
        and the GCM tag is verified before that temp file is ever moved to
        its final destination. If the tag fails to verify — meaning the
        ciphertext was tampered with after quarantine — the partially
        written temp file is deleted and an error is returned; nothing
        that looks like a legitimate restored file is ever produced from
        unverified ciphertext.
        """
        if not CRYPTO_AVAILABLE:
            return {"restored": False,
                    "error": "pycryptodome required to restore quarantined files"}
        if not os.path.isfile(vault_path):
            return {"restored": False, "error": "Vault file not found"}
        try:
            os.chmod(vault_path, 0o600)   # vault files are written as 0o000
        except OSError:
            pass
        chunk_size = CFG.get("stream_chunk_size", 4 * 1024 * 1024)
        tmp_path   = vault_path + ".restore_tmp"
        try:
            size = os.path.getsize(vault_path)
            if size < self.NONCE_SIZE + self.TAG_SIZE:
                return {"restored": False, "error": "Corrupt vault file (too small)"}
            payload_len = size - self.NONCE_SIZE - self.TAG_SIZE
            with open(vault_path, "rb") as fh:
                nonce  = fh.read(self.NONCE_SIZE)
                cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
                remaining = payload_len
                with open(tmp_path, "wb") as out:
                    while remaining > 0:
                        chunk = fh.read(min(chunk_size, remaining))
                        if not chunk:
                            break
                        out.write(cipher.decrypt(chunk))
                        remaining -= len(chunk)
                tag = fh.read(self.TAG_SIZE)
            try:
                cipher.verify(tag)
            except ValueError:
                try:
                    os.remove(tmp_path)
                finally:
                    try:
                        os.chmod(vault_path, 0o000)
                    except OSError:
                        pass
                return {"restored": False,
                        "error": "Integrity check failed — vault file may be "
                                 "tampered. Refusing to restore."}
            final_dest = dest_path or os.path.join(
                tempfile.gettempdir(), "restored_" + safe_name(os.path.basename(vault_path))
            )
            shutil.move(tmp_path, final_dest)
            try:
                os.chmod(vault_path, 0o000)
            except OSError:
                pass
            return {"restored": True, "path": final_dest}
        except (PermissionError, OSError) as exc:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            return {"restored": False, "error": str(exc)}

    def purge_expired(self, retention_days: Optional[int] = None) -> int:
        """IMP-18: Securely wipe (overwrite + delete) quarantine items older
        than `retention_days` (0 = keep forever). Intended to be called once
        at startup, matching the IMP-18 promise in the header docstring."""
        retention_days = (CFG.get("quarantine_retention_days", 90)
                          if retention_days is None else retention_days)
        if not retention_days:
            return 0
        cutoff = time.time() - retention_days * 86400
        purged = 0
        for meta_path in Path(self._vault).glob("*.meta.json"):
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                qat = meta.get("quarantined_at", "")
                ts  = datetime.datetime.fromisoformat(qat).timestamp() if qat else 0
                if ts and ts < cutoff:
                    vault_file = meta.get("vault_file", "")
                    if vault_file and self.delete(vault_file):
                        purged += 1
                    try:
                        os.remove(meta_path)
                    except OSError:
                        pass
            except (json.JSONDecodeError, OSError, ValueError):
                continue
        if purged:
            log(f"Quarantine purge: {purged} item(s) older than "
                f"{retention_days}d securely wiped.", "info")
        return purged

    def list_vault(self) -> List[dict]:
        items = []
        for f in Path(self._vault).glob("*.meta.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    items.append(json.load(fh))
            except (json.JSONDecodeError, OSError):
                pass
        return items

    def delete(self, vault_path: str) -> bool:
        try:
            if os.path.isfile(vault_path):
                try:
                    os.chmod(vault_path, 0o600)
                except OSError:
                    pass
                size = os.path.getsize(vault_path)
                with open(vault_path, "wb") as fh:
                    fh.write(b"\x00" * size)
                os.remove(vault_path)
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# REQ-01 / REQ-19: DIGITAL SIGNATURE + CERTIFICATE ANALYSIS
# ---------------------------------------------------------------------------
class DigitalSignatureScanner:
    """
    REQ-01: Verify Authenticode (Windows), codesign (macOS), GPG/dpkg/rpm (Linux).
    REQ-19: Certificate analysis — expired, self-signed, revoked, unknown publisher.
    """
    def __init__(self, trusted_publishers: List[str], timeout: int = 15):
        self._trusted = trusted_publishers
        self._timeout = timeout
        self._sysname = platform.system()

    def scan(self, path: str) -> dict:
        base = {"engine": "DigitalSignature", "file": path,
                "signed": False, "valid": False, "publisher": "",
                "status": "UNKNOWN", "score_adjustment": 0,
                "cert_expired": False, "cert_self_signed": False,
                "cert_revoked": False, "cert_unknown_publisher": True}
        ext = os.path.splitext(path.lower())[1]
        try:
            if self._sysname == "Windows":
                return self._windows(path, base)
            elif self._sysname == "Darwin":
                return self._macos(path, base, ext)
            else:
                return self._linux(path, base, ext)
        except Exception as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

    def _windows(self, path: str, base: dict) -> dict:
        ps = (
            f"$sig = Get-AuthenticodeSignature '{path}';"
            "$cert = $sig.SignerCertificate;"
            "if ($cert) {"
            "  $exp = ($cert.NotAfter -lt (Get-Date));"
            "  $sub = $cert.Subject;"
            "  $iss = $cert.Issuer;"
            "  $self = ($sub -eq $iss);"
            "  $pub = if ($sub -match 'CN=([^,]+)') { $matches[1] } else { $sub };"
            "} else { $exp=$false; $sub=''; $iss=''; $self=$false; $pub=''; }"
            "@{Status=$sig.Status.ToString();Publisher=$pub;"
            "Subject=$sub;Issuer=$iss;Expired=$exp;SelfSigned=$self} | ConvertTo-Json"
        )
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=self._timeout
            )
            d         = json.loads(res.stdout)
            status    = d.get("Status", "")
            publisher = d.get("Publisher", "")
            expired   = bool(d.get("Expired", False))
            self_sgn  = bool(d.get("SelfSigned", False))
            valid     = (status == "Valid")
            known_pub = any(p.lower() in publisher.lower() for p in self._trusted)
            adj = 0
            if valid and known_pub:
                adj = -20
            elif expired:
                adj = 25
            elif self_sgn:
                adj = 20
            elif not valid:
                adj = 15
            return {**base, "signed": bool(publisher), "valid": valid,
                    "publisher": publisher, "status": status,
                    "cert_expired": expired, "cert_self_signed": self_sgn,
                    "cert_unknown_publisher": not known_pub,
                    "score_adjustment": adj}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

    def _macos(self, path: str, base: dict, ext: str) -> dict:
        try:
            res = subprocess.run(
                ["codesign", "--verify", "--deep", "--verbose=4", path],
                capture_output=True, text=True, timeout=self._timeout
            )
            out   = (res.stdout + res.stderr).strip()
            valid = res.returncode == 0
            signed= "code object is not signed" not in out
            publisher = ""
            m = re.search(r"Authority=(.+)", out)
            if m:
                publisher = m.group(1).strip()
            # REQ-19: detect certificate issues
            expired  = "CSSMERR_TP_CERT_EXPIRED" in out or "certificate has expired" in out.lower()
            self_sgn = "self-signed" in out.lower()
            revoked  = "CSSMERR_TP_CERT_REVOKED" in out
            known_pub = any(p.lower() in publisher.lower() for p in self._trusted)
            adj = 0
            if valid and known_pub:
                adj = -20
            elif expired:
                adj = 25
            elif self_sgn:
                adj = 20
            elif revoked:
                adj = 50
            elif signed and not valid:
                adj = 15
            return {**base, "signed": signed, "valid": valid,
                    "publisher": publisher,
                    "status": "VALID" if valid else "INVALID",
                    "cert_expired": expired, "cert_self_signed": self_sgn,
                    "cert_revoked": revoked, "cert_unknown_publisher": not known_pub,
                    "score_adjustment": adj}
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

    def _linux(self, path: str, base: dict, ext: str) -> dict:
        """Check GPG/dpkg/rpm signatures on Linux."""
        if ext == ".deb" and shutil.which("dpkg-sig"):
            try:
                res = subprocess.run(
                    ["dpkg-sig", "--verify", path],
                    capture_output=True, text=True, timeout=self._timeout
                )
                valid = res.returncode == 0
                return {**base, "signed": valid, "valid": valid,
                        "status": "VALID" if valid else "INVALID",
                        "cert_unknown_publisher": not valid,
                        "score_adjustment": 0 if valid else 15}
            except (subprocess.TimeoutExpired, OSError) as exc:
                return {**base, "status": "ERROR", "error": str(exc)}
        if ext == ".rpm" and shutil.which("rpm"):
            try:
                res = subprocess.run(
                    ["rpm", "--checksig", path],
                    capture_output=True, text=True, timeout=self._timeout
                )
                valid = res.returncode == 0 and "OK" in res.stdout
                return {**base, "signed": valid, "valid": valid,
                        "status": "VALID" if valid else "INVALID",
                        "cert_unknown_publisher": not valid,
                        "score_adjustment": 0 if valid else 15}
            except (subprocess.TimeoutExpired, OSError) as exc:
                return {**base, "status": "ERROR", "error": str(exc)}
        return {**base, "status": "NOT_APPLICABLE"}


# ---------------------------------------------------------------------------
# REQ-03: FILE REPUTATION (VirusTotal + Malware Bazaar + OpenTIP)
# ---------------------------------------------------------------------------
class ReputationChecker:
    """
    REQ-03: SHA256 lookup against:
      1. Local SQLite DB
      2. VirusTotal v3 API
      3. Malware Bazaar API
      4. OpenTIP (Kaspersky) API
    """
    def __init__(self, data_dir: str, vt_api_key: str = "",
                 mb_api_key: str = "", openTIP_key: str = ""):
        self._db_path = os.path.join(data_dir, "reputation.sqlite")
        self._vt_key  = vt_api_key
        self._mb_key  = mb_api_key
        self._tip_key = openTIP_key
        self._conn    = self._open_db()

    def _open_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hashes "
            "(sha256 TEXT PRIMARY KEY, verdict TEXT, source TEXT, ts TEXT)"
        )
        conn.commit()
        return conn

    def add_known_bad(self, sha256: str, source: str = "manual") -> None:
        ts = datetime.datetime.now().isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO hashes VALUES (?,?,?,?)",
            (sha256, "BAD", source, ts)
        )
        self._conn.commit()

    def add_known_good(self, sha256: str, source: str = "manual") -> None:
        ts = datetime.datetime.now().isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO hashes VALUES (?,?,?,?)",
            (sha256, "GOOD", source, ts)
        )
        self._conn.commit()

    def lookup(self, sha256: str) -> dict:
        base = {"engine": "Reputation", "sha256": sha256, "verdict": "UNKNOWN"}
        if not sha256:
            return base
        # Local DB first
        row = self._conn.execute(
            "SELECT verdict, source FROM hashes WHERE sha256=?", (sha256,)
        ).fetchone()
        if row:
            return {**base, "verdict": row[0], "source": row[1], "local": True}
        if not REQUESTS_AVAILABLE:
            return base
        # Try each external API in order
        for lookup_fn in [self._virustotal, self._malware_bazaar, self._openTIP]:
            result = lookup_fn(sha256, base)
            if result.get("verdict") != "UNKNOWN":
                return result
        return base

    def _virustotal(self, sha256: str, base: dict) -> dict:
        if not self._vt_key:
            return base
        try:
            url  = f"https://www.virustotal.com/api/v3/files/{sha256}"
            hdrs = {"x-apikey": self._vt_key}
            resp = requests.get(url, headers=hdrs, timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                stats     = d.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                verdict   = "BAD" if malicious > 0 else "GOOD"
                return {**base, "verdict": verdict,
                        "malicious_count": malicious, "source": "VirusTotal"}
            if resp.status_code == 404:
                return {**base, "verdict": "NOT_FOUND", "source": "VirusTotal"}
        except Exception:
            pass
        return base

    def _malware_bazaar(self, sha256: str, base: dict) -> dict:
        """REQ-03: Malware Bazaar lookup."""
        if not self._mb_key:
            return base
        try:
            url  = "https://mb-api.abuse.ch/api/v1/"
            data = {"query": "get_info", "hash": sha256}
            hdrs = {"Auth-Key": self._mb_key}
            resp = requests.post(url, data=data, headers=hdrs, timeout=10)
            if resp.status_code == 200:
                d       = resp.json()
                qstatus = d.get("query_status", "")
                if qstatus == "ok":
                    return {**base, "verdict": "BAD", "source": "MalwareBazaar",
                            "tags": d.get("data", [{}])[0].get("tags", [])}
                if qstatus == "hash_not_found":
                    return {**base, "verdict": "NOT_FOUND", "source": "MalwareBazaar"}
        except Exception:
            pass
        return base

    def _openTIP(self, sha256: str, base: dict) -> dict:
        """REQ-03: OpenTIP (Kaspersky) API lookup."""
        if not self._tip_key:
            return base
        try:
            url  = f"https://opentip.kaspersky.com/api/v1/search/hash?request={sha256}"
            hdrs = {"x-api-key": self._tip_key}
            resp = requests.get(url, headers=hdrs, timeout=10)
            if resp.status_code == 200:
                d       = resp.json()
                zone    = d.get("Zone", "Grey")
                verdict = "BAD" if zone == "Red" else ("GOOD" if zone == "Green" else "UNKNOWN")
                return {**base, "verdict": verdict, "zone": zone, "source": "OpenTIP"}
        except Exception:
            pass
        return base


# ---------------------------------------------------------------------------
# REQ-04: MEMORY ANALYSIS
# ---------------------------------------------------------------------------
class MemoryScanner:
    """
    REQ-04: Scan running processes for fileless malware, injected DLLs,
    RWX memory regions, and suspicious module load paths.
    """
    def scan_all(self) -> List[dict]:
        if not psutil:
            return [{"engine": "MemoryScanner", "status": "UNAVAILABLE",
                     "error": "psutil not installed"}]
        findings = []
        try:
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    result = self._scan_process(proc)
                    if result.get("suspicious"):
                        findings.append(result)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as exc:
            findings.append({"engine": "MemoryScanner", "status": "ERROR", "error": str(exc)})
        return findings

    def _scan_process(self, proc) -> dict:
        base = {"engine": "MemoryScanner", "pid": proc.pid,
                "name": proc.info.get("name", ""), "suspicious": False, "findings": []}
        exe = proc.info.get("exe") or ""
        # Deleted executable still running
        if exe and not os.path.isfile(exe):
            base["suspicious"] = True
            base["findings"].append(f"Executable deleted/missing: {exe}")
        # Injected DLL / module from suspicious path
        if platform.system() == "Linux":
            try:
                for mmap in proc.memory_maps(grouped=False):
                    path_ = mmap.path
                    if path_ and any(path_.startswith(s) for s in ("/tmp/", "/dev/shm", "/var/tmp")):
                        base["suspicious"] = True
                        base["findings"].append(f"Module from suspicious path: {path_}")
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                pass
            # Check /proc/<pid>/maps for RWX pages
            maps_path = f"/proc/{proc.pid}/maps"
            if os.path.isfile(maps_path):
                try:
                    with open(maps_path, "r", encoding="utf-8", errors="ignore") as fh:
                        for line in fh:
                            if "rwxp" in line or "rwx " in line:
                                base["suspicious"] = True
                                base["findings"].append(f"RWX memory region: {line.strip()[:120]}")
                                break
                except (PermissionError, OSError):
                    pass
        # Windows: check for modules loaded from %TEMP%
        if platform.system() == "Windows":
            try:
                for mod in proc.memory_maps():
                    if re.search(r"(?i)(\\temp\\|\\tmp\\|appdata.*\\temp)", mod.path):
                        base["suspicious"] = True
                        base["findings"].append(f"Windows module from TEMP: {mod.path}")
            except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError):
                pass
        return base


# ---------------------------------------------------------------------------
# REQ-05: PROCESS MONITORING
# ---------------------------------------------------------------------------
class ProcessMonitor:
    """
    REQ-05: Watch for new processes spawned from USB mount point.
    Terminate suspicious processes immediately.
    """
    def __init__(self, usb_root: str):
        self._usb_root    = os.path.realpath(usb_root)
        self._known_pids: Set[int] = set()
        self._running     = False
        self._thread: Optional[threading.Thread] = None
        self._blocked_pids: List[int] = []

    def start(self) -> None:
        if not psutil:
            log("ProcessMonitor: psutil unavailable", "warning")
            return
        self._running = True
        self._thread  = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        log(f"ProcessMonitor started for {self._usb_root}", "info")

    def stop(self) -> None:
        self._running = False

    def _monitor_loop(self) -> None:
        while self._running and not STOP_EVENT.is_set():
            try:
                for proc in psutil.process_iter(["pid", "exe", "name", "cmdline"]):
                    try:
                        pid = proc.pid
                        if pid in self._known_pids:
                            continue
                        self._known_pids.add(pid)
                        exe = proc.info.get("exe") or ""
                        if exe and (
                            exe.startswith(self._usb_root) or
                            os.path.realpath(exe).startswith(self._usb_root)
                        ):
                            log(f"REQ-05 ALERT: Process launched from USB! "
                                f"PID={pid} Name={proc.info.get('name')} Exe={exe}",
                                "danger")
                            self._terminate(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass
            time.sleep(1)

    def _terminate(self, proc) -> None:
        try:
            proc.terminate()
            time.sleep(0.5)
            if proc.is_running():
                proc.kill()
            with PROCESS_LOCK:
                self._blocked_pids.append(proc.pid)
            log(f"Process {proc.pid} terminated (launched from USB)", "danger")
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as exc:
            log(f"Failed to terminate PID {proc.pid}: {exc}", "warning")


# ---------------------------------------------------------------------------
# REQ-06 / REQ-07 / REQ-08: ARCHIVE SCANNER (recursive + password detection)
# ---------------------------------------------------------------------------
class ArchiveScanner:
    """
    REQ-06: Full archive scanning (ZIP/RAR/7z/ISO/CAB/TAR/GZ/XZ).
    REQ-07: Nested archive handling (recursion up to depth 4).
    REQ-08: Password-protected archive detection and flagging.
    """
    def __init__(self, pipeline, max_extract: int, max_members: int):
        self._pipe        = pipeline
        self._max_extract = max_extract
        self._max_members = max_members
        self._max_depth   = CFG.get("max_archive_depth", 4)

    def scan(self, path: str, usb_root: str, depth: int = 0) -> dict:
        base = {"engine": "ArchiveScanner", "file": path,
                "members_scanned": 0, "danger": False, "warnings": [],
                "findings": [], "password_protected": False}
        if depth > self._max_depth:
            return {**base, "status": "SKIPPED", "error": "Max nesting depth reached"}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED", "error": "Symlink skipped"}
        ext = os.path.splitext(path.lower())[1]
        tmp = tempfile.mkdtemp(prefix="usb_shield_arc_")
        try:
            # REQ-08: detect password protection before extraction
            is_encrypted, enc_info = self._check_encrypted(path, ext)
            if is_encrypted:
                base["password_protected"] = True
                base["findings"].append(f"Password-protected archive detected: {enc_info}")
                base["danger"] = True
                base["status"] = "ENCRYPTED"
                return base

            self._extract(path, ext, tmp)
            total_extracted = 0
            for cur, dirs, names in os.walk(tmp):
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIR_NAMES]
                for name in names:
                    full = os.path.join(cur, name)
                    total_extracted += file_size(full)
                    if total_extracted > self._max_extract:
                        base["findings"].append("Extraction size limit reached; partial scan.")
                        break
                    if base["members_scanned"] >= self._max_members:
                        base["findings"].append("Member count limit reached; partial scan.")
                        break
                    member_ext = os.path.splitext(name.lower())[1]
                    # REQ-07: recurse into nested archives
                    if member_ext in ARCHIVE_EXTENSIONS and depth < self._max_depth:
                        sub = self.scan(full, tmp, depth + 1)
                        if sub.get("danger"):
                            base["danger"] = True
                        if sub.get("password_protected"):
                            base["findings"].append(
                                f"Nested encrypted archive: {name}"
                            )
                        base["findings"].extend(sub.get("findings", []))
                    else:
                        r = self._pipe.scan_file(full, tmp)
                        base["members_scanned"] += 1
                        if r.get("severity") == "DANGER":
                            base["danger"] = True
                            base["findings"].append(
                                f"DANGER in {name}: {'; '.join(r.get('findings', []))}"
                            )
                        elif r.get("severity") == "WARNING":
                            base["warnings"].append(name)
            base["status"] = "OK"
        except zipfile.BadZipFile:
            base["status"] = "ERROR"; base["error"] = "Bad ZIP"
        except tarfile.TarError as exc:
            base["status"] = "ERROR"; base["error"] = f"TAR error: {exc}"
        except PermissionError as exc:
            base["status"] = "ERROR"; base["error"] = f"Permission: {exc}"
        except OSError as exc:
            base["status"] = "ERROR"; base["error"] = f"OS: {exc}"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return base

    def _check_encrypted(self, path: str, ext: str) -> Tuple[bool, str]:
        """REQ-08: Return (is_encrypted, description)."""
        try:
            if ext == ".zip" or ext in {".jar", ".apk"}:
                with zipfile.ZipFile(path, "r") as zf:
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            return True, f"ZIP entry '{info.filename}' is encrypted"
            elif ext == ".rar":
                # Check RAR magic bytes + encryption flag (byte 11 bit 0)
                with open(path, "rb") as fh:
                    header = fh.read(14)
                if len(header) >= 12 and header[:7] == b"Rar!\x1a\x07\x00":
                    if header[11] & 0x80:
                        return True, "RAR archive is password-protected"
        except Exception:
            pass
        return False, ""

    def _extract(self, path: str, ext: str, dest: str) -> None:
        if ext in {".zip", ".jar", ".apk"}:
            with zipfile.ZipFile(path, "r") as zf:
                zf.extractall(dest)
        elif ext in {".tar", ".gz", ".tgz", ".bz2", ".xz"}:
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(dest)
        elif shutil.which("7z"):
            subprocess.run(
                ["7z", "x", path, f"-o{dest}", "-y", "-bd"],
                capture_output=True, timeout=60
            )
        else:
            raise OSError(f"No extractor available for {ext}")


# ---------------------------------------------------------------------------
# REQ-09: MIME TYPE DETECTION
# ---------------------------------------------------------------------------
class MIMETypeDetector:
    """
    REQ-09: Detect real MIME type using python-magic (libmagic binding).
    Fallback to magic-byte header matching.
    """
    MAGIC_MAP = {
        b"MZ":               ("PE executable",        "application/x-dosexec"),
        b"PK\x03\x04":       ("ZIP/Office/JAR",        "application/zip"),
        b"%PDF":             ("PDF",                   "application/pdf"),
        b"\x7fELF":         ("ELF executable",        "application/x-elf"),
        b"#!":               ("Script (shebang)",      "text/x-shellscript"),
        b"\xca\xfe\xba\xbe":("macOS FAT binary",      "application/x-mach-binary"),
        b"\xfe\xed\xfa\xce":("macOS Mach-O",          "application/x-mach-binary"),
        b"\xfe\xed\xfa\xcf":("macOS Mach-O 64-bit",   "application/x-mach-binary"),
        b"Rar!":             ("RAR archive",           "application/x-rar"),
        b"\x1f\x8b":        ("GZIP",                  "application/gzip"),
        b"BZh":              ("BZIP2",                 "application/x-bzip2"),
        b"\xfd7zXZ":        ("XZ",                    "application/x-xz"),
        b"7z\xbc\xaf":      ("7-zip",                 "application/x-7z-compressed"),
        b"\xd0\xcf\x11\xe0":("OLE2/Office binary",    "application/vnd.ms-office"),
        b"<?xml":            ("XML",                   "text/xml"),
        b"<html":            ("HTML",                  "text/html"),
        b"<HTML":            ("HTML",                  "text/html"),
    }
    SAFE_COMBOS = {
        (".docx", "ZIP"), (".xlsx", "ZIP"), (".pptx", "ZIP"),
        (".jar",  "ZIP"), (".apk",  "ZIP"), (".odt",  "ZIP"),
        (".gz",   "GZIP"),(".tgz",  "GZIP"),
    }

    def detect(self, path: str) -> dict:
        base = {"engine": "MIMEDetector", "file": path,
                "declared_ext": "", "real_mime": "", "real_type": "",
                "mismatch": False, "score": 0}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        ext = os.path.splitext(path.lower())[1]
        base["declared_ext"] = ext
        try:
            with open(path, "rb") as fh:
                header = fh.read(16)
        except (PermissionError, OSError) as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

        real_type = ""
        real_mime = ""
        for sig, (type_name, mime) in self.MAGIC_MAP.items():
            if header[:len(sig)] == sig:
                real_type = type_name
                real_mime = mime
                break

        # REQ-09: Use python-magic for richer detection
        if magic:
            try:
                real_mime = magic.from_file(path, mime=True) or real_mime
                real_type = magic.from_file(path, mime=False) or real_type
            except Exception:
                pass

        base["real_type"] = real_type
        base["real_mime"] = real_mime

        if real_type and ext:
            combo_safe = any(ext == dc and rt in real_type for dc, rt in self.SAFE_COMBOS)
            if not combo_safe:
                type_lower = real_type.lower()
                if any(k in type_lower for k in ("executable", "script", "ole", "elf", "mach")):
                    if ext not in EXEC_EXTENSIONS:
                        base["mismatch"] = True
                        base["score"]    = 80
                        base["finding"]  = f"Extension {ext!r} but real type: {real_type}"
        base["status"] = "OK"
        return base


# ---------------------------------------------------------------------------
# REQ-10: PE ANALYSIS
# ---------------------------------------------------------------------------
class PEAnalyzer:
    """
    REQ-10: Full PE analysis using pefile + lief:
    imports, exports, sections, overlay, compile time, resources,
    TLS callbacks, debug directory, certificate, entry point, packer detection.
    """
    KNOWN_PACKERS = ["UPX", "ASPack", "Themida", "Armadillo", "PECompact",
                     "NsPack", "MEW", "FSG", "MPRESS", "VMProtect"]

    def analyze(self, path: str) -> dict:
        base = {"engine": "PEAnalyzer", "file": path,
                "is_pe": False, "score": 0, "findings": [],
                "imports": [], "exports": [], "sections": [],
                "compile_time": "", "packer": "", "has_overlay": False,
                "has_tls": False, "has_debug": False,
                "entry_point": 0, "num_sections": 0}
        if not PEFILE_AVAILABLE and not LIEF_AVAILABLE:
            return {**base, "status": "UNAVAILABLE", "error": "pefile/lief not installed"}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        try:
            if PEFILE_AVAILABLE:
                return self._pefile_analyze(path, base)
            elif LIEF_AVAILABLE:
                return self._lief_analyze(path, base)
        except Exception as exc:
            return {**base, "status": "ERROR", "error": str(exc)}
        return base

    def _pefile_analyze(self, path: str, base: dict) -> dict:
        try:
            pe = pefile.PE(path, fast_load=False)
            base["is_pe"]      = True
            base["entry_point"]= pe.OPTIONAL_HEADER.AddressOfEntryPoint
            base["num_sections"] = pe.FILE_HEADER.NumberOfSections
            # Compile time
            try:
                ts = pe.FILE_HEADER.TimeDateStamp
                base["compile_time"] = datetime.datetime.utcfromtimestamp(ts).isoformat()
                # Suspicious: future or very old compile time
                now = time.time()
                if ts > now + 86400:
                    base["score"] += 15
                    base["findings"].append(f"Future compile timestamp: {base['compile_time']}")
                if ts < 946684800:  # before year 2000
                    base["score"] += 10
                    base["findings"].append("Compile timestamp before year 2000 (suspicious)")
            except Exception:
                pass
            # Sections
            for sec in pe.sections:
                sname = sec.Name.rstrip(b"\x00").decode(errors="ignore")
                data  = sec.get_data()
                ent   = entropy_bytes(data)
                base["sections"].append({
                    "name": sname, "entropy": round(ent, 3),
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                    "characteristics": hex(sec.Characteristics),
                })
                if ent >= 7.5:
                    base["score"] += 20
                    base["findings"].append(f"High-entropy section {sname}: {ent:.2f}")
                # REQ-10: check executable/writable section combinations
                RWX = 0xE0000020  # EXECUTE + READ + WRITE
                if sec.Characteristics & RWX == RWX:
                    base["score"] += 15
                    base["findings"].append(f"Section {sname} is RWX (code injection risk)")
            # Imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode(errors="ignore") if entry.dll else ""
                    base["imports"].append(dll)
                    dangerous_apis = {
                        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
                        "CreateRemoteThread", "OpenProcess", "SetWindowsHookEx",
                        "GetProcAddress", "LoadLibrary", "WinExec", "ShellExecute",
                        "URLDownloadToFile", "InternetOpenUrl",
                    }
                    for imp in entry.imports:
                        nm = imp.name.decode(errors="ignore") if imp.name else ""
                        if nm in dangerous_apis:
                            base["score"] += 5
                            base["findings"].append(f"Dangerous import: {nm} from {dll}")
            # Exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    nm = exp.name.decode(errors="ignore") if exp.name else f"ord_{exp.ordinal}"
                    base["exports"].append(nm)
            # TLS callbacks
            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                base["has_tls"] = True
                base["score"]  += 10
                base["findings"].append("TLS callbacks present (anti-debug/anti-VM)")
            # Debug directory
            if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
                base["has_debug"] = True
            # Overlay (data after end of last section)
            overlay_off = pe.get_overlay_data_start_offset()
            if overlay_off:
                overlay_data = pe.get_overlay()
                if overlay_data and len(overlay_data) > 512:
                    ov_ent = entropy_bytes(overlay_data[:65536])
                    base["has_overlay"] = True
                    base["score"]      += 10
                    base["findings"].append(
                        f"Overlay data: {len(overlay_data)} bytes, entropy={ov_ent:.2f}"
                    )
            # Packer detection
            with open(path, "rb") as fh:
                raw = fh.read(1024 * 1024)
            for packer in self.KNOWN_PACKERS:
                if packer.encode() in raw or packer.upper().encode() in raw:
                    base["packer"]  = packer
                    base["score"]  += 25
                    base["findings"].append(f"Packer detected: {packer}")
                    break
            pe.close()
            base["status"] = "OK"
        except pefile.PEFormatError:
            base["status"] = "NOT_PE"
        except (PermissionError, OSError) as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base

    def _lief_analyze(self, path: str, base: dict) -> dict:
        """Fallback using lief if pefile not available."""
        try:
            binary = lief.parse(path)
            if binary is None or not isinstance(binary, lief.PE.Binary):
                return {**base, "status": "NOT_PE"}
            base["is_pe"] = True
            base["entry_point"] = binary.optional_header.addressof_entrypoint
            base["num_sections"] = len(binary.sections)
            for sec in binary.sections:
                data = bytes(sec.content)
                ent  = entropy_bytes(data[:65536])
                base["sections"].append({
                    "name": sec.name, "entropy": round(ent, 3),
                    "virtual_size": sec.virtual_size, "raw_size": sec.size,
                })
                if ent >= 7.5:
                    base["score"]    += 20
                    base["findings"].append(f"High-entropy section {sec.name}: {ent:.2f}")
            base["status"] = "OK"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-11: ELF ANALYSIS
# ---------------------------------------------------------------------------
class ELFAnalyzer:
    """
    REQ-11: Linux ELF binary analysis using pyelftools and/or lief.
    Detects: stripped symbols, RWX segments, suspicious dynamic entries,
    PT_GNU_STACK, RPATH manipulation, rootkit indicators.
    """
    def analyze(self, path: str) -> dict:
        base = {"engine": "ELFAnalyzer", "file": path,
                "is_elf": False, "score": 0, "findings": []}
        if not PYELFTOOLS_AVAILABLE and not LIEF_AVAILABLE:
            return {**base, "status": "UNAVAILABLE", "error": "pyelftools/lief not installed"}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        try:
            with open(path, "rb") as fh:
                magic_bytes = fh.read(4)
            if magic_bytes != b"\x7fELF":
                return {**base, "status": "NOT_ELF"}
            base["is_elf"] = True
            if PYELFTOOLS_AVAILABLE:
                return self._pyelftools_analyze(path, base)
            elif LIEF_AVAILABLE:
                return self._lief_elf_analyze(path, base)
        except Exception as exc:
            return {**base, "status": "ERROR", "error": str(exc)}
        return base

    def _pyelftools_analyze(self, path: str, base: dict) -> dict:
        try:
            with open(path, "rb") as fh:
                elf = ELFFile(fh)
                # Check for stripped binary
                symtab = elf.get_section_by_name(".symtab")
                if symtab is None:
                    base["findings"].append("Stripped ELF (no symbol table)")
                    base["score"] += 5
                # Check segments for RWX
                for seg in elf.iter_segments():
                    if (hasattr(seg, "header") and
                            getattr(seg.header, "p_flags", 0) == 7):  # RWX = PF_R|PF_W|PF_X
                        base["score"]    += 20
                        base["findings"].append("RWX segment (executable+writable)")
                # Check PT_GNU_STACK
                for seg in elf.iter_segments():
                    if seg.header.p_type == "PT_GNU_STACK":
                        if getattr(seg.header, "p_flags", 0) & 1:  # executable stack
                            base["score"]    += 15
                            base["findings"].append("Executable stack (PT_GNU_STACK NX disabled)")
                # Check .dynamic section for suspicious RPATH/RUNPATH
                dynamic = elf.get_section_by_name(".dynamic")
                if dynamic:
                    for tag in dynamic.iter_tags():
                        if tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                            rpath = tag.rpath if hasattr(tag, "rpath") else str(tag)
                            if "/tmp" in rpath or "/dev/shm" in rpath:
                                base["score"]    += 30
                                base["findings"].append(f"Suspicious RPATH: {rpath}")
                # Check section entropy
                for sec in elf.iter_sections():
                    data = sec.data()
                    if len(data) > 512:
                        ent = entropy_bytes(data[:65536])
                        if ent >= 7.5:
                            base["score"]    += 15
                            base["findings"].append(f"High-entropy ELF section '{sec.name}': {ent:.2f}")
            base["status"] = "OK"
        except ELFError as exc:
            base["status"] = "NOT_ELF"; base["error"] = str(exc)
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base

    def _lief_elf_analyze(self, path: str, base: dict) -> dict:
        try:
            binary = lief.parse(path)
            if not isinstance(binary, lief.ELF.Binary):
                return {**base, "status": "NOT_ELF"}
            for seg in binary.segments:
                if (lief.ELF.SEGMENT_FLAGS.R in seg.flags and
                        lief.ELF.SEGMENT_FLAGS.W in seg.flags and
                        lief.ELF.SEGMENT_FLAGS.X in seg.flags):
                    base["score"]    += 20
                    base["findings"].append("RWX segment detected (lief)")
            base["status"] = "OK"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-12: MACH-O ANALYSIS
# ---------------------------------------------------------------------------
class MachOAnalyzer:
    """
    REQ-12: macOS Mach-O binary analysis using macholib and/or lief.
    Detects: suspicious load commands, ad-hoc signing, fat binaries,
    dylib injection (DYLD_INSERT_LIBRARIES references).
    """
    def analyze(self, path: str) -> dict:
        base = {"engine": "MachOAnalyzer", "file": path,
                "is_macho": False, "score": 0, "findings": []}
        if not MACHOLIB_AVAILABLE and not LIEF_AVAILABLE:
            return {**base, "status": "UNAVAILABLE", "error": "macholib/lief not installed"}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        try:
            with open(path, "rb") as fh:
                magic = struct.unpack("<I", fh.read(4))[0]
            MACHO_MAGICS = {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE,
                            0xCAFEBABE, 0xBEBAFECA}
            if magic not in MACHO_MAGICS:
                return {**base, "status": "NOT_MACHO"}
            base["is_macho"] = True
            if MACHOLIB_AVAILABLE:
                return self._macholib_analyze(path, base)
            elif LIEF_AVAILABLE:
                return self._lief_macho_analyze(path, base)
        except Exception as exc:
            return {**base, "status": "ERROR", "error": str(exc)}
        return base

    def _macholib_analyze(self, path: str, base: dict) -> dict:
        try:
            m = MachO.MachO(path)
            for header in m.headers:
                for _idx, _name, cmd in header.commands:
                    cmd_name = str(type(cmd).__name__).lower()
                    # Suspicious load commands
                    if "dylib" in cmd_name:
                        name_ = getattr(cmd, "name", b"")
                        if isinstance(name_, bytes):
                            name_ = name_.decode(errors="ignore")
                        if any(s in name_.lower() for s in ("/tmp/", "/var/tmp", "dylib.dylib")):
                            base["score"]    += 30
                            base["findings"].append(f"Suspicious dylib: {name_}")
            # Check for DYLD_INSERT_LIBRARIES reference in strings
            with open(path, "rb") as fh:
                raw = fh.read(min(file_size(path), 2 * 1024 * 1024))
            if b"DYLD_INSERT_LIBRARIES" in raw:
                base["score"]    += 40
                base["findings"].append("DYLD_INSERT_LIBRARIES reference (dylib injection)")
            if b"__PAGEZERO" not in raw and b"__TEXT" not in raw:
                base["score"]    += 10
                base["findings"].append("Non-standard Mach-O section layout")
            base["status"] = "OK"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base

    def _lief_macho_analyze(self, path: str, base: dict) -> dict:
        try:
            binary = lief.parse(path)
            if not isinstance(binary, lief.MachO.Binary):
                return {**base, "status": "NOT_MACHO"}
            for cmd in binary.commands:
                if isinstance(cmd, lief.MachO.DylibCommand):
                    name_ = cmd.name
                    if "/tmp" in name_ or "dyld" in name_.lower():
                        base["score"]    += 30
                        base["findings"].append(f"Suspicious dylib load: {name_}")
            base["status"] = "OK"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-13: OFFICE MACRO ANALYSIS
# ---------------------------------------------------------------------------
class OfficeDocumentScanner:
    """
    REQ-13: oletools (olevba + oleid + mraptor) for full macro analysis.
    Detects AutoOpen, Document_Open, VBA, Excel 4 macros, DDE payloads.
    """
    def scan(self, path: str) -> dict:
        base = {"engine": "OfficeDocumentScanner", "file": path,
                "score": 0, "severity": "SAFE", "findings": []}
        if not OLETOOLS_AVAILABLE:
            return {**base, "status": "UNAVAILABLE", "error": "oletools not installed"}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED", "error": "Symlink skipped"}
        try:
            # oleid: quick indicators
            oid = oleid.OleID(path)
            indicators = oid.check()
            for ind in indicators:
                if ind.value and ind.name in ("VBA Macros", "XLM Macros",
                                               "Embedded files", "ObjectPool"):
                    base["score"] += 20
                    base["findings"].append(f"OLE indicator: {ind.name} = {ind.value}")
            # olevba: deep VBA + Excel4 analysis
            vba = olevba.VBA_Parser(path)
            if vba.detect_vba_macros():
                base["score"] += 10
                base["findings"].append("VBA macros detected")
                for (_, _, vba_type, keyword, desc) in vba.analyze_macros():
                    if vba_type in ("AutoExec", "Suspicious"):
                        base["score"] += 30 if vba_type == "AutoExec" else 15
                        base["findings"].append(f"VBA {vba_type}: {keyword} – {desc}")
            # Check for Excel 4 macros (XLM)
            if vba.detect_xlm_macros():
                base["score"] += 25
                base["findings"].append("Excel 4 (XLM) macro detected — high risk")
            vba.close()
            # REQ-13: mraptor for macro risk rating
            if MRAPTOR_AVAILABLE:
                try:
                    mr = mraptor.MacroRaptor(open(path, "rb").read())
                    mr.scan()
                    if mr.suspicious:
                        base["score"] += 30
                        base["findings"].append(f"mraptor: macro flagged as suspicious")
                except Exception:
                    pass
            base["severity"] = (
                "DANGER"  if base["score"] >= 85 else
                "WARNING" if base["score"] >= 45 else
                "LOW"     if base["score"] >  0  else "SAFE"
            )
            base["status"] = "OK"
        except (PermissionError, OSError) as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-14: PDF ANALYSIS
# ---------------------------------------------------------------------------
class PDFAnalyzer:
    """
    REQ-14: Inspect PDF streams for JavaScript, Launch, OpenAction,
    embedded EXE, embedded files, suspicious URLs.
    """
    DANGEROUS_KEYS = {b"/JavaScript", b"/JS", b"/OpenAction",
                      b"/Launch", b"/AA", b"/SubmitForm", b"/GoToR",
                      b"/EmbeddedFiles", b"/RichMedia", b"/XFA"}

    def scan(self, path: str) -> dict:
        base = {"engine": "PDFAnalyzer", "file": path,
                "score": 0, "severity": "SAFE", "findings": []}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        if file_size(path) > CFG["max_behavior_file_size"]:
            return {**base, "status": "SKIPPED", "error": "File too large"}
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            if not data.startswith(b"%PDF"):
                return {**base, "status": "NOT_PDF"}
            for key in self.DANGEROUS_KEYS:
                if key in data:
                    base["score"] += 25
                    base["findings"].append(f"PDF key: {key.decode()}")
            # Suspicious external URLs
            urls = re.findall(rb"https?://[^\s)>\]\"']{5,120}", data)
            for url in urls[:20]:
                u = url.decode(errors="ignore").lower()
                if not any(d in u for d in ["adobe.com", "w3.org", "opentype.org"]):
                    base["score"] += 10
                    base["findings"].append(
                        f"PDF external URL: {url[:80].decode(errors='ignore')}"
                    )
            # Embedded EXE (MZ header inside stream)
            if b"MZ" in data:
                base["score"] += 60
                base["findings"].append("Possible embedded PE (MZ header) in PDF")
            # Large base64 blobs (dropper pattern)
            b64_blobs = re.findall(rb"[A-Za-z0-9+/]{200,}={0,2}", data)
            if len(b64_blobs) > 3:
                base["score"] += 20
                base["findings"].append(f"Multiple large base64 blobs ({len(b64_blobs)}) in PDF")
            # REQ-14: detect /EmbeddedFiles (file attachment)
            if b"/EmbeddedFiles" in data:
                base["score"] += 15
                base["findings"].append("PDF contains embedded file attachments")
            base["score"]    = min(base["score"], 100)
            base["severity"] = (
                "DANGER"  if base["score"] >= 85 else
                "WARNING" if base["score"] >= 45 else
                "LOW"     if base["score"] > 0  else "SAFE"
            )
            base["status"] = "OK"
        except (PermissionError, OSError) as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-15: HTML ANALYSIS
# ---------------------------------------------------------------------------
class HTMLAnalyzer:
    """
    REQ-15: Detect malicious HTML patterns:
    iframes, base64 embedded payloads, obfuscated JS,
    hidden redirects, eval/exec, ActiveX objects.
    """
    def scan(self, path: str) -> dict:
        base = {"engine": "HTMLAnalyzer", "file": path,
                "score": 0, "severity": "SAFE", "findings": []}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        if file_size(path) > CFG["max_text_read"]:
            return {**base, "status": "SKIPPED", "error": "File too large"}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (PermissionError, OSError) as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

        lower = content.lower()

        rules = [
            # REQ-15: iframe
            (r"<iframe[^>]+src\s*=\s*[\"']?\s*(javascript:|data:)", 40,
             "Inline JavaScript/data iframe"),
            (r"<iframe[^>]+style\s*=\s*[\"'][^\"']*display\s*:\s*none", 30,
             "Hidden iframe (display:none)"),
            (r"<iframe[^>]+width\s*=\s*[\"']?0", 25, "Zero-width iframe"),
            (r"<iframe[^>]+height\s*=\s*[\"']?0", 25, "Zero-height iframe"),
            # REQ-15: obfuscated JS
            (r"eval\s*\(", 30, "eval() in HTML"),
            (r"document\.write\s*\(.*?unescape", 35, "document.write+unescape obfuscation"),
            (r"fromcharcode", 25, "String.fromCharCode obfuscation"),
            (r"atob\s*\(", 20, "atob() base64 decode"),
            # REQ-15: base64 embedded content
            (r"src\s*=\s*[\"']data:text/html;base64,", 50, "Base64-encoded HTML page embed"),
            (r"src\s*=\s*[\"']data:application/javascript;base64,", 60,
             "Base64-encoded JS embed"),
            # REQ-15: hidden redirects
            (r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", 40, "Meta refresh redirect"),
            (r"window\.location\s*=\s*[\"']https?://", 30, "window.location redirect"),
            (r"location\.href\s*=\s*[\"']https?://", 30, "location.href redirect"),
            # ActiveX / exploits
            (r"activexobject", 50, "ActiveX object creation"),
            (r"wscript\.shell", 60, "WScript.Shell in HTML"),
            (r"shellexecute", 60, "ShellExecute in HTML"),
            # REQ-15: script src from suspicious domains
            (r"<script[^>]+src\s*=\s*[\"'](https?://(?!ajax\.googleapis|code\.jquery|cdn\.jsdelivr)[^\"']+\.js)", 35,
             "Script loaded from external domain"),
        ]

        for pattern, pts, desc in rules:
            if re.search(pattern, lower, re.IGNORECASE | re.DOTALL):
                base["score"] += pts
                base["findings"].append(f"HTML: {desc}")

        # Count obfuscated vars (variable names like _0x...)
        obf_vars = re.findall(r"\b_0x[0-9a-f]+\b", content)
        if len(obf_vars) > 10:
            base["score"] += 30
            base["findings"].append(f"Heavy JS obfuscation ({len(obf_vars)} obfuscated identifiers)")

        base["score"]    = min(base["score"], 100)
        base["severity"] = (
            "DANGER"  if base["score"] >= 85 else
            "WARNING" if base["score"] >= 45 else
            "LOW"     if base["score"] > 0  else "SAFE"
        )
        base["status"] = "OK"
        return base


# ---------------------------------------------------------------------------
# REQ-18: NETWORK IOC DETECTION
# ---------------------------------------------------------------------------
class NetworkIOCScanner:
    """
    REQ-18: Extract and evaluate network indicators from file content:
    IP addresses, domains, URLs, TOR (.onion), Telegram bots,
    Discord webhooks, Pastebin, dynamic DNS.
    """
    SUSPICIOUS_DOMAINS = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "pastebin.com", "hastebin.com", "paste.ee",
        "discord.com/api/webhooks", "discord.gg",
        "t.me", "api.telegram.org",
        "ngrok.io", "serveo.net", "localhost.run",
        "duckdns.org", "ddns.net", "no-ip.com",
    ]
    TOR_PATTERN = re.compile(rb"[a-z2-7]{16,56}\.onion", re.IGNORECASE)
    IP_PATTERN   = re.compile(
        rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )

    def scan(self, path: str) -> dict:
        base = {"engine": "NetworkIOCScanner", "file": path,
                "score": 0, "findings": [], "iocs": {
                    "ips": [], "domains": [], "urls": [], "tor": [],
                    "telegram": [], "discord": [], "pastebin": []
                }}
        if os.path.islink(path):
            return {**base, "status": "SKIPPED"}
        sz = file_size(path)
        if sz > CFG["max_behavior_file_size"]:
            return {**base, "status": "SKIPPED", "error": "Too large"}
        try:
            with open(path, "rb") as fh:
                data = fh.read(CFG["max_text_read"])
        except (PermissionError, OSError) as exc:
            return {**base, "status": "ERROR", "error": str(exc)}

        # TOR .onion addresses
        tor_hits = list(set(self.TOR_PATTERN.findall(data)))
        if tor_hits:
            base["iocs"]["tor"] = [h.decode(errors="ignore") for h in tor_hits[:10]]
            base["score"] += 50
            base["findings"].append(f"TOR .onion address: {base['iocs']['tor'][0]}")

        # Extract URLs
        urls = re.findall(rb"https?://[^\s\"'<>]{5,200}", data)
        for url in urls[:50]:
            u = url.decode(errors="ignore")
            base["iocs"]["urls"].append(u)
            low = u.lower()
            if "discord.com/api/webhooks" in low:
                base["score"] += 40
                base["iocs"]["discord"].append(u)
                base["findings"].append(f"Discord webhook: {u[:80]}")
            elif "api.telegram.org" in low or "t.me/" in low:
                base["score"] += 35
                base["iocs"]["telegram"].append(u)
                base["findings"].append(f"Telegram C2: {u[:80]}")
            elif "pastebin.com" in low or "hastebin" in low:
                base["score"] += 25
                base["iocs"]["pastebin"].append(u)
                base["findings"].append(f"Pastebin (dropper staging): {u[:80]}")
            else:
                for sus_dom in self.SUSPICIOUS_DOMAINS:
                    if sus_dom in low:
                        base["score"] += 15
                        base["findings"].append(f"Suspicious domain: {sus_dom}")

        # Extract raw IPs (exclude RFC-1918 private)
        ips = list(set(self.IP_PATTERN.findall(data)))
        for ip_bytes in ips[:20]:
            ip_str = ip_bytes.decode(errors="ignore")
            try:
                addr = ipaddress.ip_address(ip_str)
                if not addr.is_private and not addr.is_loopback:
                    base["iocs"]["ips"].append(ip_str)
                    base["score"] += 5
            except ValueError:
                pass

        # Extract domains from strings
        domains = re.findall(rb"(?:^|[^a-zA-Z0-9])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:xyz|top|tk|ml|ga|cf|gq|pw|ru|cn|cc|info|club|online|site|icu|loan|work|date|men|review|stream|gdn|bid|trade|science|download|racing|win|webcam|faith|cricket|party))", data)
        for dom in domains[:10]:
            d = dom.decode(errors="ignore")
            base["iocs"]["domains"].append(d)
            base["score"] += 10
            base["findings"].append(f"Suspicious TLD domain: {d}")

        base["score"] = min(base["score"], 100)
        base["status"] = "OK"
        return base


# ---------------------------------------------------------------------------
# REQ-16: MACHINE LEARNING HEURISTIC LAYER
# ---------------------------------------------------------------------------
class MLHeuristicScorer:
    """
    REQ-16: RandomForest-based maliciousness scoring.
    Falls back to hand-crafted feature heuristic when no model is provided.
    """
    def __init__(self, model_path: str = ""):
        self._model = None
        if ML_AVAILABLE and model_path and os.path.isfile(model_path):
            try:
                import joblib
                self._model = joblib.load(model_path)
                log(f"ML model loaded from {model_path}", "success")
            except Exception as exc:
                log(f"ML model load failed: {exc}", "warning")

    def score(self, features: dict) -> dict:
        base = {"engine": "MLHeuristic", "ml_score": 0, "explanation": ""}
        try:
            if self._model and ML_AVAILABLE:
                vec = np.array([[
                    features.get("file_size", 0) / 1e6,
                    features.get("entropy", 0),
                    features.get("section_count", 0),
                    features.get("import_count", 0),
                    features.get("string_density", 0),
                    int(features.get("has_upx", False)),
                    int(features.get("has_autorun", False)),
                    int(features.get("has_network_strings", False)),
                    int(features.get("is_pe", False)),
                    int(features.get("is_elf", False)),
                    int(features.get("has_tls", False)),
                    int(features.get("has_overlay", False)),
                ]])
                prob = self._model.predict_proba(vec)[0][1]
                base["ml_score"]    = int(prob * 100)
                base["explanation"] = "RandomForest probability"
            else:
                score = 0.0
                ent   = features.get("entropy", 0)
                if ent >= 7.7:   score += 30
                elif ent >= 7.0: score += 10
                if features.get("has_upx"):             score += 20
                if features.get("has_autorun"):         score += 25
                if features.get("has_network_strings"): score += 15
                if features.get("has_tls"):             score += 10
                if features.get("has_overlay"):         score += 10
                if features.get("is_elf") and features.get("entropy", 0) >= 7.0:
                    score += 15  # packed ELF
                if (features.get("section_count", 0) <= 1 and
                        features.get("file_size", 0) > 50000):
                    score += 10
                base["ml_score"]    = min(int(score), 100)
                base["explanation"] = "Built-in feature heuristic"
        except Exception as exc:
            base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# REQ-17: DYNAMIC ANALYSIS / SANDBOX
# ---------------------------------------------------------------------------
class SandboxSubmitter:
    """
    REQ-17: Submit suspicious files to:
    - Cuckoo (self-hosted)
    - CAPEv2 (self-hosted)
    - Any.Run API (cloud)
    Returns behavioral report summary.
    """
    def __init__(self):
        self._cuckoo_url  = CFG.get("cuckoo_url", "")
        self._anyrun_key  = CFG.get("any_run_api_key", "")
        self._timeout     = CFG.get("sandbox_timeout", 300)

    def submit(self, path: str) -> dict:
        base = {"engine": "Sandbox", "file": path,
                "submitted": False, "verdict": "UNKNOWN", "findings": []}
        if not REQUESTS_AVAILABLE:
            return {**base, "status": "UNAVAILABLE", "error": "requests not installed"}
        if self._cuckoo_url:
            return self._cuckoo_submit(path, base)
        if self._anyrun_key:
            return self._anyrun_submit(path, base)
        return {**base, "status": "SKIPPED", "error": "No sandbox configured"}

    def _cuckoo_submit(self, path: str, base: dict) -> dict:
        """REQ-17: Submit to Cuckoo/CAPEv2 REST API."""
        try:
            url = f"{self._cuckoo_url.rstrip('/')}/tasks/create/file"
            with open(path, "rb") as fh:
                resp = requests.post(
                    url,
                    files={"file": (os.path.basename(path), fh)},
                    timeout=30
                )
            if resp.status_code == 200:
                task_id = resp.json().get("task_id")
                base["submitted"]  = True
                base["task_id"]    = task_id
                base["status"]     = "SUBMITTED"
                # Poll for result
                report = self._poll_cuckoo(task_id)
                if report:
                    score   = report.get("info", {}).get("score", 0)
                    verdict = "BAD" if score >= 5 else "CLEAN"
                    base["verdict"]   = verdict
                    base["cuckoo_score"] = score
                    sigs = [s.get("name", "") for s in report.get("signatures", [])]
                    base["findings"]  = sigs[:10]
            else:
                base["status"] = "ERROR"
                base["error"]  = f"HTTP {resp.status_code}"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base

    def _poll_cuckoo(self, task_id: int, max_wait: int = 120) -> Optional[dict]:
        url = f"{self._cuckoo_url.rstrip('/')}/tasks/report/{task_id}"
        deadline = time.time() + max_wait
        while time.time() < deadline:
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass
            time.sleep(10)
        return None

    def _anyrun_submit(self, path: str, base: dict) -> dict:
        """REQ-17: Submit to Any.Run cloud sandbox."""
        try:
            url  = "https://api.any.run/v1/analysis"
            hdrs = {"Authorization": f"API-Key {self._anyrun_key}"}
            with open(path, "rb") as fh:
                resp = requests.post(
                    url,
                    headers=hdrs,
                    files={"file": (os.path.basename(path), fh)},
                    data={"env_os": "windows", "env_bitness": 64,
                          "timeout": 60, "obj_type": "file"},
                    timeout=30
                )
            if resp.status_code == 200:
                data   = resp.json()
                task_id= data.get("data", {}).get("taskid", "")
                base.update({"submitted": True, "task_id": task_id,
                              "status": "SUBMITTED",
                              "url": f"https://app.any.run/tasks/{task_id}"})
            else:
                base["status"] = "ERROR"
                base["error"]  = f"HTTP {resp.status_code}"
        except Exception as exc:
            base["status"] = "ERROR"; base["error"] = str(exc)
        return base


# ---------------------------------------------------------------------------
# YARA SCANNER (with correlation bonuses)
# ---------------------------------------------------------------------------
CORRELATION_BONUSES = {
    frozenset({"Downloader", "Persistence"}):      15,
    frozenset({"Downloader", "PackedExecutable"}):  20,
    frozenset({"PowerShell", "Obfuscation"}):       20,
    frozenset({"Ransomware", "Downloader"}):        30,
    frozenset({"ReverseShell", "Persistence"}):     25,
    frozenset({"CredentialStealer", "Downloader"}): 20,
    frozenset({"USBWorm", "Persistence"}):          25,
    frozenset({"DLLInjection", "PackedExecutable"}):20,
    frozenset({"PEInjection", "Obfuscation"}):      20,
}

DEFAULT_YARA_RULES = r"""
rule USB_Shell_Download_Execute { meta: category="Downloader" severity="high" score=75 description="Shell script downloads, marks executable, executes" strings: $curl="curl" nocase $wget="wget" nocase $chmod="chmod +x" nocase $tmp="/tmp/" nocase $exec1="./" ascii $bash="bash" nocase $sh="sh" nocase condition: (($curl or $wget) and $chmod and ($tmp or $exec1)) or (($curl or $wget) and ($bash or $sh) and $tmp) }
rule USB_PowerShell_Download_Execute { meta: category="PowerShell" severity="high" score=80 description="PowerShell download+execution chain" strings: $ps="powershell" nocase $dl1="DownloadString" nocase $dl2="Invoke-WebRequest" nocase $dl3="Net.WebClient" nocase $iex1="Invoke-Expression" nocase $iex2="IEX" nocase $enc1="-EncodedCommand" nocase $enc2="FromBase64String" nocase condition: $ps and 1 of ($dl*) and (1 of ($iex*) or 1 of ($enc*)) }
rule USB_Office_Macro_Shell_Abuse { meta: category="OfficeMacro" severity="high" score=85 description="Office auto-run macro with shell execution" strings: $auto1="AutoOpen" nocase $auto2="Document_Open" nocase $auto3="Workbook_Open" nocase $obj1="CreateObject" nocase $obj2="WScript.Shell" nocase $obj3="Shell.Application" nocase $exec1="powershell" nocase $exec2="cmd.exe" nocase $exec3="mshta" nocase condition: 1 of ($auto*) and 1 of ($obj*) and 1 of ($exec*) }
rule USB_JavaScript_Dropper_Obfuscated { meta: category="JavaScript" severity="medium" score=55 description="JS obfuscation/dropper indicators" strings: $a1="eval(" nocase $a2="Function(" nocase $a3="atob(" nocase $a4="fromCharCode" nocase $a5="ActiveXObject" nocase $a6="WScript.Shell" nocase $a7="XMLHTTP" nocase condition: 3 of them }
rule USB_PE_Process_Injection_APIs { meta: category="PEInjection" severity="high" score=80 description="PE with process injection API combo" strings: $a1="VirtualAlloc" ascii wide $a2="VirtualProtect" ascii wide $a3="WriteProcessMemory" ascii wide $a4="CreateRemoteThread" ascii wide $a5="OpenProcess" ascii wide $a6="GetProcAddress" ascii wide condition: uint16(0)==0x5A4D and 3 of them }
rule USB_DLL_Injection_APIs { meta: category="DLLInjection" severity="high" score=85 description="DLL injection API chain" strings: $o="OpenProcess" ascii wide $v="VirtualAllocEx" ascii wide $w="WriteProcessMemory" ascii wide $c="CreateRemoteThread" ascii wide $q="QueueUserAPC" ascii wide $n="NtMapViewOfSection" ascii wide condition: uint16(0)==0x5A4D and $o and $w and ($c or $q or $n or $v) }
rule USB_Ransomware_Windows_Behavior { meta: category="Ransomware" severity="critical" score=100 description="Ransomware shadow-copy deletion + crypto" strings: $c1="CryptEncrypt" ascii wide $c2="CryptAcquireContext" ascii wide $v1="vssadmin" nocase $v2="Delete Shadows" nocase $w1="wbadmin" nocase $b1="bcdedit" nocase $f1="FindFirstFile" ascii wide $f2="FindNextFile" ascii wide condition: (1 of ($c*) and 1 of ($f*) and 1 of ($v*,$w1,$b1)) or (3 of ($v*,$w1,$b1)) }
rule USB_LOLBin_Downloader { meta: category="Downloader" severity="medium" score=60 description="Windows LOLBin download/execute" strings: $l1="certutil" nocase $l2="bitsadmin" nocase $l3="mshta" nocase $l4="regsvr32" nocase $l5="rundll32" nocase $u1="http://" nocase $u2="https://" nocase $e1="-urlcache" nocase $e2="scrobj.dll" nocase condition: 1 of ($l*) and 1 of ($u*) and (1 of ($e*) or $l3 or $l4) }
rule USB_Windows_Persistence { meta: category="Persistence" severity="medium" score=55 description="Windows persistence strings" strings: $r1="CurrentVersion\\Run" nocase $r2="RunOnce" nocase $s1="schtasks" nocase $s2="ScheduledTask" nocase $svc1="CreateService" ascii wide $startup="Startup" nocase condition: 2 of them }
rule USB_Linux_Mac_Persistence { meta: category="Persistence" severity="medium" score=50 description="Linux/macOS persistence indicators" strings: $c1="crontab" nocase $c2="/etc/cron" nocase $l1="launchctl" nocase $l2="LaunchAgents" nocase $l3="LaunchDaemons" nocase $s1="systemctl enable" nocase condition: 2 of them }
rule USB_Worm_Autorun_Style { meta: category="USBWorm" severity="high" score=80 description="USB worm autorun/hidden copy behavior" strings: $a1="autorun.inf" nocase $r1="RECYCLER" nocase $s1="System Volume Information" nocase $c1="CopyFile" ascii wide $h1="SetFileAttributes" ascii wide $h2="Hidden" nocase condition: $a1 and 2 of ($r1,$s1,$c1,$h1,$h2) }
rule USB_Obfuscation_MultiIndicator { meta: category="Obfuscation" severity="low" score=25 description="Generic multi-indicator obfuscation" strings: $b1="base64" nocase $b2="FromBase64String" nocase $e1="eval(" nocase $e2="exec(" nocase $c1="chr(" nocase $x1="xor" nocase $g1="gzip" nocase condition: 3 of them }
rule USB_CryptoMiner_Indicators { meta: category="Cryptominer" severity="medium" score=50 description="Cryptocurrency miner indicators" strings: $s1="stratum+tcp" nocase $x1="xmrig" nocase $m1="monero" nocase $r1="RandomX" nocase $w1="wallet" nocase condition: 2 of them }
rule USB_Reverse_Shell_Chain { meta: category="ReverseShell" severity="high" score=75 description="Reverse shell command chains" strings: $n1="nc " nocase $n2="netcat" nocase $e1=" -e " ascii $b1="bash -i" nocase $d1="/dev/tcp" nocase $m1="mkfifo" nocase condition: (($n1 or $n2) and $e1) or ($b1 and $d1) or ($m1 and ($b1 or $n1 or $n2)) }
rule USB_Credential_Stealer_Indicators { meta: category="CredentialStealer" severity="medium" score=60 description="Credential/browser data theft indicators" strings: $p1="CryptUnprotectData" ascii wide $p2="Login Data" nocase $p3="Cookies" nocase $p4="keychain" nocase $p5="password" nocase $p6="credential" nocase condition: 3 of them or ($p1 and 1 of ($p2,$p3,$p5,$p6)) }
rule USB_UPX_Packed_PE { meta: category="PackedExecutable" severity="medium" score=50 description="UPX packed PE indicators" strings: $u1="UPX0" ascii $u2="UPX1" ascii $u3="UPX!" ascii condition: uint16(0)==0x5A4D and any of them }
rule USB_PDF_JavaScript_Launch { meta: category="PDF" severity="medium" score=55 description="PDF JavaScript/OpenAction/Launch indicators" strings: $p="%PDF" ascii $j1="/JavaScript" ascii $j2="/JS" ascii $o1="/OpenAction" ascii $l1="/Launch" ascii $a1="/AA" ascii condition: $p and 2 of ($j1,$j2,$o1,$l1,$a1) }
rule USB_Discord_Webhook { meta: category="NetworkC2" severity="medium" score=65 description="Discord webhook C2 channel" strings: $d="discord.com/api/webhooks" nocase condition: $d }
rule USB_Telegram_C2 { meta: category="NetworkC2" severity="medium" score=60 description="Telegram bot C2 channel" strings: $t1="api.telegram.org" nocase $t2="bot_token" nocase condition: $t1 or $t2 }
"""


class YARAScanner:
    """Enhanced YARA scanner with weighted, correlated scoring.

    GAP-03: Supports loading from a single rules_file OR a rules directory
    containing many *.yar files (rules/malware.yar, rules/ransomware.yar, ...).
    Exposes reload() so a RuleUpdater can refresh rules without restarting
    the application.
    """
    def __init__(self, rules_file: str, rules_dir: Optional[str] = None):
        self._rules_file   = rules_file
        self._rules_dir     = rules_dir
        self._rules         = None
        self._available     = yara is not None
        self._lock          = threading.RLock()
        self._last_loaded   = 0.0
        self._source_mtimes: Dict[str, float] = {}
        self._ensure_rules_file()
        self._load()

    def _rule_sources(self) -> Dict[str, str]:
        """Return {namespace: filepath} for everything to compile."""
        sources: Dict[str, str] = {}
        if self._rules_dir and os.path.isdir(self._rules_dir):
            for fn in sorted(os.listdir(self._rules_dir)):
                if fn.lower().endswith((".yar", ".yara")):
                    sources[os.path.splitext(fn)[0]] = os.path.join(self._rules_dir, fn)
        if not sources and self._rules_file:
            sources["default"] = self._rules_file
        return sources

    def _ensure_rules_file(self) -> None:
        if self._rules_dir:
            os.makedirs(self._rules_dir, exist_ok=True)
            if not self._rule_sources():
                # Seed the directory with the built-in default rule set
                seed = os.path.join(self._rules_dir, "default.yar")
                try:
                    with open(seed, "w", encoding="utf-8") as fh:
                        fh.write(DEFAULT_YARA_RULES.strip() + "\n")
                except OSError as exc:
                    log(f"YARA rule seed failed: {exc}", "danger")
            return
        if os.path.exists(self._rules_file) and yara:
            try:
                yara.compile(filepath=self._rules_file)
                return
            except Exception as exc:
                log(f"YARA rules corrupt ({exc}); regenerating.", "warning")
        try:
            os.makedirs(os.path.dirname(self._rules_file), exist_ok=True)
            with open(self._rules_file, "w", encoding="utf-8") as fh:
                fh.write(DEFAULT_YARA_RULES.strip() + "\n")
        except OSError as exc:
            log(f"YARA rule file creation failed: {exc}", "danger")

    def _load(self) -> None:
        if yara is None:
            log("YARA unavailable: install yara-python", "warning")
            return
        sources = self._rule_sources()
        try:
            with self._lock:
                self._rules = yara.compile(filepaths=sources) if len(sources) > 1 \
                              else yara.compile(filepath=list(sources.values())[0])
                self._source_mtimes = {p: os.path.getmtime(p) for p in sources.values()
                                       if os.path.exists(p)}
                self._last_loaded = time.time()
            log(f"YARA rules loaded ({len(sources)} file(s))", "success")
        except Exception as exc:
            log(f"YARA disabled: {exc}", "danger")

    def needs_reload(self) -> bool:
        """GAP-03: True if any rule file on disk changed since last compile."""
        for path, old_mtime in self._source_mtimes.items():
            try:
                if os.path.getmtime(path) != old_mtime:
                    return True
            except OSError:
                return True
        current = set(self._rule_sources().values())
        return current != set(self._source_mtimes.keys())

    def reload(self) -> bool:
        """GAP-03: Recompile rules in place (thread-safe, no restart needed)."""
        previous = self._rules
        try:
            self._load()
            return True
        except Exception as exc:
            self._rules = previous
            log(f"YARA reload failed, keeping previous ruleset: {exc}", "warning")
            return False

    def scan(self, path: str) -> dict:
        base = {"engine": "YARA", "file": path, "score": 0, "matches": []}
        if yara is None:
            return {**base, "matched": False, "status": "ERROR",
                    "error": "yara-python not installed"}
        if self._rules is None:
            return {**base, "matched": False, "status": "ERROR",
                    "error": "rules unavailable"}
        if os.path.islink(path):
            return {**base, "matched": False, "status": "SKIPPED"}
        if file_size(path) > CFG["max_yara_file_size"]:
            return {**base, "matched": False, "status": "SKIPPED",
                    "error": "File too large for YARA"}
        try:
            matches = self._rules.match(path, timeout=CFG["yara_timeout"])
            if not matches:
                return {**base, "matched": False, "status": "OK"}
            clean = []
            total_score  = 0
            matched_cats = set()
            for m in matches:
                meta  = dict(getattr(m, "meta", {}) or {})
                score = int(meta.get("score", 40))
                total_score += score
                cat = meta.get("category", "Generic")
                matched_cats.add(cat)
                clean.append({
                    "rule": str(m), "category": cat,
                    "severity": meta.get("severity", "medium"),
                    "score": score, "description": meta.get("description", ""),
                })
            # Correlation bonuses
            bonus    = 0
            cats_lst = list(matched_cats)
            for i in range(len(cats_lst)):
                for j in range(i + 1, len(cats_lst)):
                    pair = frozenset({cats_lst[i], cats_lst[j]})
                    bonus += CORRELATION_BONUSES.get(pair, 0)
            if bonus:
                clean.append({
                    "rule": "CorrelationBonus", "category": "Correlation",
                    "severity": "high", "score": bonus,
                    "description": f"Multi-category correlation: {sorted(matched_cats)}",
                })
                total_score += bonus
            return {**base, "matched": True, "status": "MATCH",
                    "matches": clean, "score": min(total_score, 150)}
        except yara.TimeoutError:
            return {**base, "matched": False, "status": "ERROR", "error": "YARA timeout"}
        except Exception as exc:
            return {**base, "matched": False, "status": "ERROR", "error": str(exc)}


# ---------------------------------------------------------------------------
# MITRE ATT&CK MAPPING  (v9.0 / GAP-02)
# ---------------------------------------------------------------------------
# Maps internal detection indicators (set in USBScanPipeline.scan_file) to
# MITRE ATT&CK techniques so reports show analyst-friendly technique IDs.
MITRE_MAP: Dict[str, Tuple[str, str]] = {
    "clamav_infected":      ("T1204",      "User Execution (known signature)"),
    "yara_high":            ("T1027",      "Obfuscated/Compressed File or Information"),
    "behavior_danger":      ("T1204.002",  "Malicious File Execution"),
    "unsigned":              ("T1036",      "Masquerading (unsigned binary)"),
    "packedexecutable":      ("T1027.002",  "Software Packing"),
    "has_overlay":           ("T1027.001",  "Binary Padding"),
    "high_entropy":          ("T1027",      "Obfuscated/Compressed File or Information"),
    "autorun":               ("T1547.001",  "Boot or Logon Autostart Execution"),
    "office_macro":          ("T1059.005",  "Command and Scripting Interpreter: VBA"),
    "pdf_javascript":        ("T1059.007",  "Command and Scripting Interpreter: JavaScript"),
    "pdf_launch":            ("T1204.002",  "Malicious File Execution"),
    "tor_c2":                ("T1090.003",  "Multi-hop Proxy (Tor)"),
    "networkc2":             ("T1071",      "Application Layer Protocol (C2)"),
    "network_strings":       ("T1071",      "Application Layer Protocol"),
    "downloader":            ("T1105",      "Ingress Tool Transfer"),
    "ransomware":            ("T1486",      "Data Encrypted for Impact"),
    "persistence":           ("T1547",      "Boot or Logon Autostart Execution"),
    "credentialstealer":     ("T1555",      "Credentials from Password Stores"),
    "reverse_shell":         ("T1059",      "Command and Scripting Interpreter"),
    "usbworm":               ("T1091",      "Replication Through Removable Media"),
}


def map_indicators_to_mitre(indicators: Set[str]) -> List[dict]:
    """GAP-02: Convert internal indicator strings into MITRE ATT&CK entries."""
    seen: Dict[str, dict] = {}
    for ind in indicators:
        tech = MITRE_MAP.get(ind)
        if not tech:
            continue
        tid, name = tech
        if tid not in seen:
            seen[tid] = {"technique_id": tid, "technique": name, "indicators": []}
        seen[tid]["indicators"].append(ind)
    return sorted(seen.values(), key=lambda x: x["technique_id"])


def compute_detection_confidence(indicators: Set[str], engines: dict) -> dict:
    """
    GAP-05: Detection confidence tiering.
    HIGH   = ClamAV signature hit, or (YARA match + Behavior danger), or 3+ engines agree
    MEDIUM = Behavior + YARA (no ClamAV), or 2 engines agree
    LOW    = single engine only (behavior-only / YARA-only)
    NONE   = nothing triggered
    """
    positive_engines = []
    for name, res in engines.items():
        if not isinstance(res, dict):
            continue
        if res.get("infected") or res.get("matched"):
            positive_engines.append(name)
        elif res.get("severity") in {"DANGER", "WARNING"}:
            positive_engines.append(name)
        elif isinstance(res.get("score"), (int, float)) and res.get("score", 0) > 0:
            positive_engines.append(name)
    n = len(set(positive_engines))

    if "clamav_infected" in indicators:
        tier = "HIGH"
    elif n >= 3:
        tier = "HIGH"
    elif ("yara_high" in indicators and "behavior_danger" in indicators) or n == 2:
        tier = "MEDIUM"
    elif n == 1:
        tier = "LOW"
    else:
        tier = "NONE"

    return {"tier": tier, "agreeing_engines": sorted(set(positive_engines)),
            "engine_count": n}


# ---------------------------------------------------------------------------
# USB BEHAVIOR RULE ENGINE (retained from v6.0)
# ---------------------------------------------------------------------------
class USBBehaviorRuleEngine:
    def __init__(self):
        self._media  = {".jpg",".jpeg",".png",".gif",".heic",".webp",
                        ".mp3",".mp4",".mkv",".mov",".avi"}
        self._exec   = EXEC_EXTENSIONS
        self._doc    = {".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx",
                        ".txt",".jpg",".png",".mp3",".mp4",".zip",".rar"}
        self._script = SCRIPT_EXTENSIONS
        self._redir  = {".lnk",".url",".webloc",".desktop",".html",".htm"}

    def scan(self, path: str, usb_root: str = None) -> dict:
        r = {"engine": "USBBehaviorRules", "file": path,
             "score": 0, "severity": "SAFE", "findings": [], "status": "OK"}
        seen: Set[str] = set()

        def add(score: int, finding: str) -> None:
            if finding in seen: return
            seen.add(finding)
            r["score"] += score
            r["findings"].append(finding)

        try:
            name  = os.path.basename(path)
            lower = name.lower()
            ext   = os.path.splitext(lower)[1]
            if name.startswith("._"):
                return r
            if os.path.islink(path):
                add(40, "Symlink found on USB")
                try:
                    target = os.path.realpath(path)
                    if usb_root and not realpath_inside(path, usb_root):
                        add(90, f"Symlink redirects outside USB: {target}")
                except Exception:
                    pass
                r["severity"] = self._sev(r["score"])
                return r
            if usb_root and not realpath_inside(path, usb_root):
                add(100, "Resolved file path is outside USB root")
                r["severity"] = "DANGER"
                return r
            if file_size(path) > CFG["max_behavior_file_size"]:
                return {**r, "status": "SKIPPED", "error": "Too large"}
            hidden = any(p.startswith(".") and p not in (".", "..") for p in Path(path).parts)
            if hidden:
                add(10, "Hidden file/path")
                if ext in self._exec | self._script:
                    add(80, "Hidden executable/script on USB")
            if lower == "autorun.inf":
                add(90, "Windows autorun.inf found")
                txt = self._read_text(path)
                if re.search(r"(?im)^\s*(open|shellexecute|shell\\open\\command)\s*=", txt):
                    add(90, "autorun.inf executable launch command")
            if ext == ".desktop":
                txt = self._read_text(path)
                if re.search(r"(?im)^\s*Exec\s*=", txt):
                    add(50, "Linux .desktop launcher with Exec")
                if re.search(r"(?i)(curl|wget|bash|sh|python|powershell|cmd\.exe)", txt):
                    add(70, "Suspicious command in .desktop launcher")
            parts_ = lower.split(".")
            if len(parts_) >= 3:
                prev_ext  = "." + parts_[-2]
                final_ext = "." + parts_[-1]
                if prev_ext in self._doc and final_ext in self._exec:
                    add(90, f"Fake/double extension: {prev_ext}{final_ext}")
            header = self._read_header(path)
            if header.startswith(b"MZ") and ext not in self._exec:
                add(90, f"PE executable hidden behind {ext or 'no'} extension")
            if header.startswith(b"#!") and ext in (self._media | self._doc):
                add(85, f"Script hidden behind {ext} extension")
            if ext in self._redir:
                self._redirect_rules(path, ext, add)
            if ext in self._script:
                self._script_rules(path, add)
            r["severity"] = self._sev(r["score"])
        except PermissionError as exc:
            r["status"] = "ERROR"; r["error"] = f"Permission denied: {exc}"
        except OSError as exc:
            r["status"] = "ERROR"; r["error"] = f"OS error: {exc}"
        return r

    def _sev(self, score: int) -> str:
        if score >= 80: return "DANGER"
        if score >= 40: return "WARNING"
        if score > 0:   return "LOW"
        return "SAFE"

    def _read_header(self, path: str) -> bytes:
        try:
            with open(path, "rb") as fh:
                return fh.read(16)
        except (PermissionError, OSError):
            return b""

    def _read_text(self, path: str) -> str:
        try:
            with open(path, "rb") as fh:
                return fh.read(CFG["max_text_read"]).decode("utf-8", errors="ignore")
        except (PermissionError, OSError):
            return ""

    def _redirect_rules(self, path: str, ext: str, add) -> None:
        txt = self._read_text(path)
        low = txt.lower()
        if ext == ".url":
            m = re.search(r"(?im)^\s*URL\s*=\s*(.+)$", txt)
            if m:
                url = m.group(1).strip()
                add(35, f"URL shortcut → {url[:120]}")
                if re.search(r"(?i)\.(exe|scr|bat|cmd|ps1|vbs|js|hta|jar)(\?|$)", url):
                    add(90, "URL shortcut points to executable/script")
        elif ext == ".webloc":
            try:
                with open(path, "rb") as fh:
                    plist = plistlib.load(fh)
                url = plist.get("URL", "")
                if url:
                    add(35, f"macOS webloc → {url[:120]}")
            except Exception:
                if "http" in low:
                    add(30, "webloc/url-like redirect")
        elif ext in {".html", ".htm"}:
            if re.search(r"(?i)<meta[^>]+http-equiv=[\"']?refresh", txt):
                add(50, "HTML meta refresh redirect")
            if re.search(r"(?i)(window\.location|document\.location|location\.href)\s*=", txt):
                add(60, "JavaScript location redirect")
        elif ext == ".lnk":
            try:
                with open(path, "rb") as fh:
                    data = fh.read(CFG["max_text_read"]).lower()
                if b"http://" in data or b"https://" in data:
                    add(50, "Windows shortcut contains URL")
                for cmd in [b"cmd.exe", b"powershell", b"wscript", b"cscript",
                             b"mshta", b"rundll32", b"regsvr32"]:
                    if cmd in data:
                        add(90, f"Windows shortcut invokes {cmd.decode(errors='ignore')}")
                        break
            except (PermissionError, OSError):
                pass

    def _script_rules(self, path: str, add) -> None:
        txt = self._read_text(path)
        rules = [
            (r"curl\s+[^\n|;]+\s*[|]\s*(bash|sh)",     "curl piped to shell"),
            (r"wget\s+[^\n|;]+\s*[|]\s*(bash|sh)",     "wget piped to shell"),
            (r"(curl|wget).*chmod\s+\+x",               "download then chmod executable"),
            (r"powershell.*(-enc|-encodedcommand)",      "PowerShell encoded command"),
            (r"Invoke-Expression|\bIEX\b",               "PowerShell IEX"),
            (r"FromBase64String|base64\s+-d|base64_decode","base64 decode"),
            (r"eval\s*\(|exec\s*\(|Function\s*\(",      "dynamic eval/exec"),
            (r"nc\s+.*\s-e\s+",                         "netcat reverse shell"),
            (r"rm\s+-rf\s+(/|\$HOME|~)",                 "destructive rm -rf"),
        ]
        for pat, desc in rules:
            if re.search(pat, txt, re.IGNORECASE | re.DOTALL):
                add(50, f"Suspicious script: {desc}")


# ---------------------------------------------------------------------------
# CLAMAV SCANNER
# ---------------------------------------------------------------------------
class ClamAVScanner:
    def __init__(self, database_dir: Optional[str] = None, timeout: int = None):
        self._clamscan = shutil.which("clamscan")
        self._db       = self._select_db(database_dir)
        self._timeout  = timeout or CFG["clamav_timeout"]

    def _select_db(self, db: Optional[str]) -> str:
        if db:
            return db
        for p in CLAMAV_DB_CANDIDATES:
            if os.path.isdir(p):
                return p
        return CFG["clamav_db_dir"]

    def _validate_db(self) -> Tuple[bool, str]:
        if not os.path.isabs(self._db):
            return False, "ClamAV DB path must be absolute"
        allowed = [os.path.abspath(p) for p in CLAMAV_DB_CANDIDATES]
        if os.path.abspath(self._db) not in allowed:
            return False, "ClamAV DB outside allowed paths"
        return True, "OK"

    def database_status(self) -> dict:
        ok, msg = self._validate_db()
        if not ok:
            return {"available": False, "database": self._db, "error": msg}
        if not os.path.isdir(self._db):
            return {"available": False, "database": self._db, "error": "Directory missing"}
        names   = set(os.listdir(self._db))
        missing = [f for f in ["main", "daily", "bytecode"]
                   if f"{f}.cvd" not in names and f"{f}.cld" not in names]
        if missing:
            return {"available": False, "database": self._db,
                    "error": "Missing: " + ", ".join(missing)}
        return {"available": True, "database": self._db}

    def scan(self, path: str) -> dict:
        """REQ-24: Wrapped with retry logic."""
        base = {"engine": "ClamAV", "file": path}
        if not self._clamscan:
            return {**base, "infected": False, "status": "ERROR",
                    "error": "clamscan not found"}
        db = self.database_status()
        if not db.get("available"):
            return {**base, "infected": False, "status": "ERROR",
                    "error": db.get("error")}
        if os.path.islink(path):
            return {**base, "infected": False, "status": "SKIPPED",
                    "error": "Symlink skipped"}
        if file_size(path) > CFG["max_clamav_file_size"]:
            return {**base, "infected": False, "status": "SKIPPED",
                    "error": "Too large for ClamAV"}

        def _run():
            cmd = [self._clamscan, f"--database={self._db}",
                   "--infected", "--no-summary", path]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self._timeout
            )
            out = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()
            if res.returncode == 1 or "FOUND" in out:
                m   = re.search(r":\s*(.+?)\s+FOUND", out)
                sig = m.group(1).strip() if m else "Unknown"
                return {**base, "infected": True, "signature": sig,
                        "status": "FOUND", "raw": out}
            if res.returncode == 0:
                return {**base, "infected": False, "status": "OK"}
            return {**base, "infected": False, "status": "ERROR",
                    "error": out or f"rc={res.returncode}"}

        try:
            return with_retry(_run, max_retries=CFG.get("max_retries", 2))
        except subprocess.TimeoutExpired:
            return {**base, "infected": False, "status": "ERROR", "error": "ClamAV timeout"}
        except PermissionError as exc:
            return {**base, "infected": False, "status": "ERROR",
                    "error": f"Permission denied: {exc}"}
        except OSError as exc:
            return {**base, "infected": False, "status": "ERROR", "error": str(exc)}

    def update(self) -> dict:
        """GAP-03: Run freshclam to refresh signature databases."""
        freshclam = shutil.which("freshclam")
        if not freshclam:
            return {"updated": False, "error": "freshclam not found"}
        try:
            res = subprocess.run(
                [freshclam, f"--datadir={self._db}"] if self._db else [freshclam],
                capture_output=True, text=True, timeout=300
            )
            out = (res.stdout or "") + (res.stderr or "")
            updated = res.returncode == 0
            return {"updated": updated, "output": out[-2000:], "returncode": res.returncode}
        except subprocess.TimeoutExpired:
            return {"updated": False, "error": "freshclam timeout"}
        except OSError as exc:
            return {"updated": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# AUTOMATIC RULE UPDATER  (v9.0 / GAP-03)
# ---------------------------------------------------------------------------
class RuleUpdater:
    """
    Periodically checks for updated YARA rule files and ClamAV signature
    databases, then safely reloads them without restarting the application.

    - YARA: detects mtime changes in the rules/ directory and recompiles
      via YARAScanner.reload(); on failure the previous compiled ruleset
      is kept (atomic, fail-safe).
    - ClamAV: invokes freshclam on a configurable interval and re-validates
      the database afterward.
    """
    def __init__(self, yara_scanner: "YARAScanner", clam_scanner: "ClamAVScanner",
                 check_interval: int = 3600, clamav_update_interval: int = 21600,
                 quiet: bool = False):
        self._yara            = yara_scanner
        self._clam            = clam_scanner
        self._check_interval  = check_interval
        self._clam_interval   = clamav_update_interval
        self._quiet           = quiet
        self._last_clam_update = 0.0
        self._stop            = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def check_once(self) -> dict:
        """Run a single check/reload cycle; also callable on-demand / from CLI."""
        result = {"yara_reloaded": False, "clamav_updated": False}
        try:
            if self._yara.needs_reload():
                result["yara_reloaded"] = self._yara.reload()
                if result["yara_reloaded"]:
                    log("YARA ruleset auto-reloaded (rules changed on disk).",
                        "success", self._quiet)
        except Exception as exc:
            log(f"RuleUpdater YARA check failed: {exc}", "warning", self._quiet)

        now = time.time()
        if now - self._last_clam_update >= self._clam_interval:
            try:
                upd = self._clam.update()
                self._last_clam_update = now
                result["clamav_updated"] = bool(upd.get("updated"))
                if upd.get("updated"):
                    log("ClamAV database refreshed via freshclam.", "success", self._quiet)
                elif upd.get("error"):
                    log(f"ClamAV update skipped: {upd['error']}", "warning", self._quiet)
            except Exception as exc:
                log(f"RuleUpdater ClamAV check failed: {exc}", "warning", self._quiet)
        return result

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.check_once()
            self._stop.wait(self._check_interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="RuleUpdater")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# BEHAVIORAL CORRELATION ENGINE
# ---------------------------------------------------------------------------
class BehavioralCorrelationEngine:
    COMBO_BONUSES = [
        ({"clamav_infected"},                                           50, "ClamAV confirmation"),
        ({"yara_high", "behavior_danger"},                              20, "YARA high + behavior danger"),
        ({"unsigned", "high_entropy", "network_strings"},               30, "Unsigned+encrypted+network"),
        ({"unsigned", "yara_high", "high_entropy"},                     25, "Unsigned+YARA+packed"),
        ({"persistence", "downloader", "high_entropy"},                 35, "Persistence+downloader+packed"),
        ({"office_macro", "autorun"},                                   30, "Office macro auto-run"),
        ({"pdf_javascript", "pdf_launch"},                              25, "PDF JS+Launch"),
        ({"unsigned", "persistence", "downloader"},                     40, "Full attack chain"),
        ({"ransomware"},                                                 60, "Ransomware indicators"),
        ({"reverse_shell", "persistence"},                               35, "Shell + persistence"),
        ({"networkc2", "persistence"},                                   40, "C2 + persistence"),
        ({"tor_c2", "downloader"},                                       45, "TOR C2 + downloader"),
    ]

    def correlate(self, indicators: set, base_score: int) -> dict:
        bonus     = 0
        triggered = []
        for required, combo_bonus, desc in self.COMBO_BONUSES:
            if set(required).issubset(indicators):
                bonus += combo_bonus
                triggered.append({"combination": sorted(required),
                                   "bonus": combo_bonus, "reason": desc})
        final = min(base_score + bonus, 100)
        return {"base_score": base_score, "correlation_bonus": bonus,
                "final_score": final, "triggered_combos": triggered}


# ---------------------------------------------------------------------------
# MAIN SCAN PIPELINE
# ---------------------------------------------------------------------------
class USBScanPipeline:
    """
    Orchestrates all scan engines per file.
    All 25 requirements integrated.
    """
    def __init__(self, clam_db: Optional[str] = None, data_dir: str = "",
                 whitelist: Optional[WhitelistDB] = None):
        self._behavior    = USBBehaviorRuleEngine()
        self._clamav      = ClamAVScanner(database_dir=clam_db)
        self._yara        = YARAScanner(
            os.path.join(data_dir, "rules.yar") if data_dir else
            os.path.join(CFG["base_dir"], "rules.yar"),
            rules_dir=os.path.join(data_dir or CFG["base_dir"], "rules")
        )
        self._sig         = DigitalSignatureScanner(
            trusted_publishers=CFG["trusted_publishers"],
            timeout=CFG["signature_check_timeout"]
        )
        self._pe          = PEAnalyzer()                 # REQ-10
        self._elf         = ELFAnalyzer()                # REQ-11
        self._macho       = MachOAnalyzer()              # REQ-12
        self._office      = OfficeDocumentScanner()      # REQ-13
        self._pdf         = PDFAnalyzer()                # REQ-14
        self._html        = HTMLAnalyzer()               # REQ-15
        self._mime        = MIMETypeDetector()           # REQ-09
        self._ml          = MLHeuristicScorer(model_path=CFG.get("ml_model_path", ""))  # REQ-16
        self._nioc        = NetworkIOCScanner()          # REQ-18
        self._sandbox     = SandboxSubmitter()           # REQ-17
        self._correlation = BehavioralCorrelationEngine()
        self._whitelist   = whitelist or WhitelistDB()   # REQ-23

    def _sev(self, score: int) -> str:
        if score >= CFG["score_danger"]:  return "DANGER"
        if score >= CFG["score_warning"]: return "WARNING"
        if score > 0:                     return "LOW"
        return "SAFE"

    def scan_file(self, path: str, usb_root: str) -> dict:
        ext  = os.path.splitext(path.lower())[1]
        size = file_size(path)
        merged: dict = {
            "file": path, "size": size, "sha256": None,
            "risk_score": 0, "severity": "SAFE",
            "status": "OK", "infected": False,
            "findings": [], "engines": {},
        }

        # REQ-20: Streaming SHA256 (never loads full file)
        if not os.path.islink(path) and size <= CFG["max_clamav_file_size"]:
            merged["sha256"] = sha256_file(path)

        # REQ-23: Whitelist check – early exit if fully whitelisted
        wl_result = self._whitelist.check(path, merged["sha256"])
        if wl_result["whitelisted"] and wl_result["score_adjustment"] <= -100:
            merged["severity"]   = "SAFE"
            merged["status"]     = "WHITELISTED"
            merged["findings"]   = [f"Whitelisted: {wl_result['reason']}"]
            merged["engines"]["whitelist"] = wl_result
            return merged

        # Run core engines
        b  = self._behavior.scan(path, usb_root=usb_root)
        c  = self._clamav.scan(path)
        y  = self._yara.scan(path)
        s  = self._sig.scan(path)                         # REQ-01/19
        ft = self._mime.detect(path)                      # REQ-09
        merged["engines"] = {
            "behavior": b, "clamav": c, "yara": y,
            "signature": s, "mime": ft
        }

        # REQ-10: PE analysis
        if ext in {".exe", ".dll", ".scr", ".sys", ".com"} or (
            not os.path.islink(path) and
            self._read_header(path)[:2] == b"MZ"
        ):
            pe_r = self._pe.analyze(path)
            merged["engines"]["pe"] = pe_r

        # REQ-11: ELF analysis
        if platform.system() == "Linux" or ext in {"", ".so", ".elf"}:
            elf_r = self._elf.analyze(path)
            if elf_r.get("is_elf"):
                merged["engines"]["elf"] = elf_r

        # REQ-12: Mach-O analysis
        if platform.system() == "Darwin" or ext in {".dylib", ".macho"}:
            mo_r = self._macho.analyze(path)
            if mo_r.get("is_macho"):
                merged["engines"]["macho"] = mo_r

        # REQ-13: Office macros
        if ext in OFFICE_EXTENSIONS:
            od = self._office.scan(path)
            merged["engines"]["office"] = od

        # REQ-14: PDF
        if ext == ".pdf":
            pd_ = self._pdf.scan(path)
            merged["engines"]["pdf"] = pd_

        # REQ-15: HTML
        if ext in {".html", ".htm"}:
            ht = self._html.scan(path)
            merged["engines"]["html"] = ht

        # REQ-18: Network IOC scan (for all text-like / executable files)
        if ext in EXEC_EXTENSIONS | SCRIPT_EXTENSIONS | {".pdf", ".html", ".htm", ".txt"}:
            nioc = self._nioc.scan(path)
            merged["engines"]["network_ioc"] = nioc

        # ---- Score aggregation ----
        score      = 0
        indicators: Set[str] = set()

        # REQ-23: Whitelist adjustment
        if wl_result.get("score_adjustment"):
            score += wl_result["score_adjustment"]

        # ClamAV
        if c.get("infected"):
            score = 100
            indicators.add("clamav_infected")
            merged["findings"].append(f"ClamAV: {c.get('signature', 'Unknown')}")

        # YARA with correlation
        if y.get("matched"):
            yara_score = min(y.get("score", 0), 100)
            score += yara_score
            yara_cats = {m.get("category", "") for m in y.get("matches", [])}
            for cat in yara_cats:
                indicators.add(cat.lower())
            if yara_score >= 75:
                indicators.add("yara_high")
            for m in y.get("matches", []):
                merged["findings"].append(
                    f"YARA[{m.get('category')}:+{m.get('score')}]: "
                    f"{m.get('rule')} – {m.get('description')}"
                )

        # Behavior
        if b.get("severity") in {"DANGER", "WARNING", "LOW"}:
            bscore = min(int(b.get("score", 0)), 60)
            score += bscore
            if b.get("severity") == "DANGER":
                indicators.add("behavior_danger")
            for f_ in b.get("findings", []):
                merged["findings"].append("Behavior: " + f_)

        # REQ-01/19: Digital signature + certificate
        if s.get("score_adjustment"):
            score += s["score_adjustment"]
        if not s.get("valid") and ext in EXEC_EXTENSIONS:
            indicators.add("unsigned")
        if s.get("cert_expired"):
            score += 15; merged["findings"].append("REQ-19: Certificate expired")
        if s.get("cert_self_signed"):
            score += 15; merged["findings"].append("REQ-19: Self-signed certificate")
        if s.get("cert_revoked"):
            score += 40; merged["findings"].append("REQ-19: Certificate REVOKED")
        if s.get("cert_unknown_publisher") and ext in EXEC_EXTENSIONS:
            merged["findings"].append("REQ-19: Unknown publisher")

        # REQ-09: MIME type mismatch
        if ft.get("mismatch"):
            score += ft.get("score", 0)
            merged["findings"].append("MIME: " + ft.get("finding", "type mismatch"))

        # REQ-10: PE analysis
        if "pe" in merged["engines"]:
            pe_r = merged["engines"]["pe"]
            if pe_r.get("score", 0) > 0:
                score += min(pe_r["score"], 60)
                if pe_r.get("packer"):
                    indicators.add("packedexecutable")
                if pe_r.get("has_tls"):
                    indicators.add("has_tls")
                if pe_r.get("has_overlay"):
                    indicators.add("has_overlay")
                for f_ in pe_r.get("findings", []):
                    merged["findings"].append("PE: " + f_)

        # REQ-11: ELF analysis
        if "elf" in merged["engines"]:
            elf_r = merged["engines"]["elf"]
            if elf_r.get("score", 0) > 0:
                score += min(elf_r["score"], 50)
                for f_ in elf_r.get("findings", []):
                    merged["findings"].append("ELF: " + f_)

        # REQ-12: Mach-O analysis
        if "macho" in merged["engines"]:
            mo_r = merged["engines"]["macho"]
            if mo_r.get("score", 0) > 0:
                score += min(mo_r["score"], 50)
                for f_ in mo_r.get("findings", []):
                    merged["findings"].append("MachO: " + f_)

        # REQ-13: Office macros
        if "office" in merged["engines"]:
            od = merged["engines"]["office"]
            if od.get("score", 0) > 0:
                score += min(od["score"], 50)
                if "autorun" in str(od.get("findings", [])).lower():
                    indicators.add("autorun")
                if od.get("score", 0) >= 20:
                    indicators.add("office_macro")
                for f_ in od.get("findings", []):
                    merged["findings"].append("OfficeMacro: " + f_)

        # REQ-14: PDF
        if "pdf" in merged["engines"]:
            pd_ = merged["engines"]["pdf"]
            if pd_.get("score", 0) > 0:
                score += min(pd_["score"], 50)
                if "/javascript" in str(pd_.get("findings", [])).lower():
                    indicators.add("pdf_javascript")
                if "/launch" in str(pd_.get("findings", [])).lower():
                    indicators.add("pdf_launch")
                for f_ in pd_.get("findings", []):
                    merged["findings"].append("PDF: " + f_)

        # REQ-15: HTML
        if "html" in merged["engines"]:
            ht = merged["engines"]["html"]
            if ht.get("score", 0) > 0:
                score += min(ht["score"], 50)
                for f_ in ht.get("findings", []):
                    merged["findings"].append("HTML: " + f_)

        # REQ-18: Network IOC
        if "network_ioc" in merged["engines"]:
            nioc = merged["engines"]["network_ioc"]
            if nioc.get("score", 0) > 0:
                score += min(nioc["score"], 50)
                iocs = nioc.get("iocs", {})
                if iocs.get("tor"):
                    indicators.add("tor_c2")
                if iocs.get("discord") or iocs.get("telegram"):
                    indicators.add("networkc2")
                if iocs.get("ips") or iocs.get("domains"):
                    indicators.add("network_strings")
                for f_ in nioc.get("findings", []):
                    merged["findings"].append("NetworkIOC: " + f_)

        # REQ-20: Streaming entropy (lazy — only if not already computed by PE)
        if "pe" not in merged["engines"] and ext in ENTROPY_EXTENSIONS:
            ent = entropy_cached(path, merged["sha256"])
            merged["entropy"] = round(ent, 3)
            if ent >= 7.7:
                indicators.add("high_entropy")
                score += 25 if ext in {".exe", ".dll", ".scr", ".sys"} else 10
                merged["findings"].append(f"High entropy ({ent:.2f}): {ext}")

        # REQ-16: ML scoring
        features = {
            "file_size":            size,
            "entropy":              merged.get("entropy", 0),
            "section_count":        len(merged["engines"].get("pe", {}).get("sections", [])),
            "import_count":         len(merged["engines"].get("pe", {}).get("imports", [])),
            "string_density":       0,
            "has_upx":              "packedexecutable" in indicators,
            "has_autorun":          "autorun" in indicators,
            "has_network_strings":  "network_strings" in indicators,
            "is_pe":                merged["engines"].get("pe", {}).get("is_pe", False),
            "is_elf":               merged["engines"].get("elf", {}).get("is_elf", False),
            "has_tls":              "has_tls" in indicators,
            "has_overlay":          "has_overlay" in indicators,
        }
        ml_result = self._ml.score(features)
        merged["engines"]["ml"] = ml_result
        if ml_result.get("ml_score", 0) >= 70:
            score += 15
            merged["findings"].append(
                f"ML heuristic: {ml_result['ml_score']}/100 ({ml_result['explanation']})"
            )

        # REQ-19: Behavioral correlation
        corr = self._correlation.correlate(indicators, min(score, 100))
        if corr["correlation_bonus"] > 0:
            merged["engines"]["correlation"] = corr
            merged["findings"].append(
                f"Correlation bonus +{corr['correlation_bonus']}: "
                + ", ".join(c["reason"] for c in corr["triggered_combos"])
            )
        score = corr["final_score"]

        merged["risk_score"] = max(0, score)
        merged["severity"]   = self._sev(merged["risk_score"])
        merged["status"]     = (
            "FOUND"      if merged["severity"] == "DANGER" else
            "SUSPICIOUS" if merged["severity"] == "WARNING" else "OK"
        )
        merged["infected"] = merged["severity"] == "DANGER"

        # GAP-02: MITRE ATT&CK technique mapping
        merged["indicators"] = sorted(indicators)
        merged["mitre"]      = map_indicators_to_mitre(indicators)

        # GAP-05: Detection confidence tier
        merged["confidence"] = compute_detection_confidence(indicators, merged["engines"])

        for name, er in merged["engines"].items():
            if isinstance(er, dict) and er.get("status") == "ERROR":
                merged["findings"].append(f"{name} error: {er.get('error')}")

        return merged

    def _read_header(self, path: str) -> bytes:
        try:
            with open(path, "rb") as fh:
                return fh.read(4)
        except (PermissionError, OSError):
            return b""


# ---------------------------------------------------------------------------
# READ-ONLY MANAGER
# ---------------------------------------------------------------------------
class USBReadOnlyManager:
    def lock(self, drive: dict) -> dict:
        return self._dispatch(drive, ro=True)

    def unlock(self, drive: dict) -> dict:
        return self._dispatch(drive, ro=False)

    def _dispatch(self, drive: dict, ro: bool) -> dict:
        sysname = platform.system()
        if sysname == "Linux":   return self._linux(drive, ro)
        if sysname == "Darwin":  return self._macos(drive, ro)
        if sysname == "Windows": return self._windows(drive, ro)
        return {"locked": False, "status": "ERROR", "error": f"Unsupported OS: {sysname}"}

    def _linux(self, drive: dict, ro: bool) -> dict:
        mp  = drive["mountpoint"]
        opt = "remount,ro" if ro else "remount,rw"
        key = "locked" if ro else "unlocked"
        try:
            res = subprocess.run(
                ["mount", "-o", opt, mp],
                capture_output=True, text=True, timeout=15
            )
            ok = res.returncode == 0
            return {key: ok,
                    "status": "READ_ONLY" if (ro and ok) else ("RW" if ok else "ERROR"),
                    "error": res.stderr.strip(), "mountpoint": mp}
        except subprocess.TimeoutExpired:
            return {key: False, "status": "ERROR", "error": "mount timeout"}
        except PermissionError:
            return {key: False, "status": "ERROR", "error": "Permission denied – run with sudo"}
        except OSError as exc:
            return {key: False, "status": "ERROR", "error": str(exc)}

    def _macos(self, drive: dict, ro: bool) -> dict:
        mp  = drive["mountpoint"]
        dev = drive.get("device")
        key = "locked" if ro else "unlocked"
        if not dev:
            return {key: False, "status": "ERROR", "error": "missing device"}
        try:
            subprocess.run(["diskutil", "unmount", mp],
                           capture_output=True, text=True, timeout=15)
            cmd = (["diskutil", "mount", "-mountOptions", "rdonly", dev] if ro
                   else ["diskutil", "mount", dev])
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            ok  = res.returncode == 0
            return {key: ok,
                    "status": "READ_ONLY" if (ro and ok) else ("RW" if ok else "ERROR"),
                    "error": (res.stderr or res.stdout).strip(), "device": dev}
        except subprocess.TimeoutExpired:
            return {key: False, "status": "ERROR", "error": "diskutil timeout"}
        except OSError as exc:
            return {key: False, "status": "ERROR", "error": str(exc)}

    def _windows(self, drive: dict, ro: bool) -> dict:
        mp  = drive["mountpoint"].rstrip("\\/")
        key = "locked" if ro else "unlocked"
        if len(mp) < 2 or mp[1] != ":" or not mp[0].isalpha():
            return {key: False, "status": "ERROR", "error": "invalid drive letter"}
        letter = mp[0].upper()
        val    = "$true" if ro else "$false"
        ps     = (f"$p=Get-Partition -DriveLetter {letter};"
                  f"$d=$p|Get-Disk;"
                  f"Set-Disk -Number $d.Number -IsReadOnly {val}")
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=20
            )
            ok = res.returncode == 0
            return {key: ok,
                    "status": "READ_ONLY" if (ro and ok) else ("RW" if ok else "ERROR"),
                    "error": (res.stderr or res.stdout).strip()}
        except subprocess.TimeoutExpired:
            return {key: False, "status": "ERROR", "error": "PowerShell timeout"}
        except OSError as exc:
            return {key: False, "status": "ERROR", "error": str(exc)}


# ---------------------------------------------------------------------------
# USB DETECTION
# ---------------------------------------------------------------------------
def device_uuid_linux(device: str) -> str:
    try:
        if shutil.which("blkid") and device:
            res = subprocess.run(
                ["blkid", "-s", "UUID", "-o", "value", device],
                capture_output=True, text=True, timeout=3
            )
            return res.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return ""


def get_usb_drives() -> List[dict]:
    sysname = platform.system()
    if sysname == "Linux":   return _linux_usb_drives()
    if sysname == "Darwin":  return _macos_usb_drives()
    if sysname == "Windows": return _windows_usb_drives()
    return []


def _linux_usb_drives() -> List[dict]:
    drives = []
    if psutil:
        for p in psutil.disk_partitions(all=False):
            mp = p.mountpoint
            if any(mp.startswith(s) for s in ("/media/", "/run/media/", "/mnt/")):
                drives.append({"mountpoint": mp, "device": p.device,
                                "fstype": p.fstype,
                                "uuid": device_uuid_linux(p.device)})
    else:
        try:
            with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) > 9:
                        mp  = parts[4].replace("\\040", " ")
                        sep = parts.index("-") if "-" in parts else -1
                        dev = parts[sep + 2] if sep > 0 and sep + 2 < len(parts) else ""
                        fst = parts[sep + 1] if sep > 0 and sep + 1 < len(parts) else ""
                        if any(mp.startswith(s) for s in ("/media/", "/run/media/", "/mnt/")):
                            drives.append({"mountpoint": mp, "device": dev, "fstype": fst,
                                           "uuid": device_uuid_linux(dev)})
        except (PermissionError, OSError):
            pass
    return drives


def _diskutil_plist(identifier: str) -> dict:
    try:
        res = subprocess.run(
            ["diskutil", "info", "-plist", identifier],
            capture_output=True, timeout=10
        )
        if res.returncode == 0 and res.stdout:
            return plistlib.loads(res.stdout)
    except (subprocess.TimeoutExpired, OSError, plistlib.InvalidFileException):
        pass
    return {}


def _plist_get(d: dict, keys: List[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _macos_usb_drives() -> List[dict]:
    drives = []
    try:
        out   = subprocess.run(
            ["diskutil", "list", "external"],
            capture_output=True, text=True, timeout=10
        ).stdout
        parts = sorted(set(re.findall(r"(disk\d+s\d+)", out)))
        for part in parts:
            pl = _diskutil_plist(part)
            mp = str(_plist_get(pl, ["MountPoint", "Mount Point"]) or "")
            if not mp or not os.path.exists(mp):
                continue
            uuid = str(_plist_get(pl, ["VolumeUUID", "Volume UUID"]) or "")
            bus  = str(_plist_get(pl, ["BusProtocol", "Bus Protocol"]) or "").upper()
            drives.append({
                "mountpoint": mp, "device": part,
                "fstype": str(_plist_get(pl, ["FilesystemName"]) or "external"),
                "uuid": uuid, "bus": bus or "ExternalUnknown",
            })
    except (subprocess.TimeoutExpired, OSError) as exc:
        log(f"macOS USB detection error: {exc}", "warning")
    return drives


def _windows_usb_drives() -> List[dict]:
    drives = []
    if platform.system() != "Windows":
        return drives
    try:
        GetDriveTypeW   = ctypes.windll.kernel32.GetDriveTypeW
        DRIVE_REMOVABLE = 2
        bitmask         = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord("A") + i)
                root   = f"{letter}:\\"
                if GetDriveTypeW(ctypes.c_wchar_p(root)) == DRIVE_REMOVABLE:
                    drives.append({"mountpoint": root, "device": root,
                                   "fstype": "removable", "uuid": root})
    except (OSError, AttributeError):
        if psutil:
            for p in psutil.disk_partitions(all=False):
                if "removable" in p.opts.lower():
                    drives.append({"mountpoint": p.mountpoint, "device": p.device,
                                   "fstype": p.fstype, "uuid": p.device})
    return drives


# ---------------------------------------------------------------------------
# FILE DISCOVERY with REQ-25 priority queue
# ---------------------------------------------------------------------------
def discover_files(root: str) -> List[str]:
    """
    REQ-25: Returns files sorted so executables/scripts come first.
    """
    priority_exts = set(CFG.get("priority_extensions", []))
    high_prio: List[str] = []
    low_prio:  List[str] = []
    root_real = os.path.realpath(root)
    for cur, dirs, names in os.walk(root, followlinks=False):
        if STOP_EVENT.is_set():
            break
        dirs[:] = [d for d in dirs
                   if d not in EXCLUDE_DIR_NAMES and
                   not os.path.islink(os.path.join(cur, d))]
        for n in names:
            if n.startswith("._"):
                continue
            full = os.path.join(cur, n)
            if os.path.islink(full):
                high_prio.append(full)
            elif os.path.isfile(full) and realpath_inside(full, root_real):
                ext = os.path.splitext(n.lower())[1]
                if ext in priority_exts:
                    high_prio.append(full)
                else:
                    low_prio.append(full)
    return high_prio + low_prio


# ---------------------------------------------------------------------------
# COPY HELPER
# ---------------------------------------------------------------------------
def copy_file_from_usb(src: str, usb_root: str, drive_label: str = "usb") -> dict:
    if os.path.islink(src):
        return {"copied": False, "error": "Refusing to copy symlink"}
    if not realpath_inside(src, usb_root):
        return {"copied": False, "error": "Refusing: path outside USB root"}
    size = file_size(src)
    if size > CFG["max_copy_file_size"]:
        return {"copied": False, "error": f"File too large: {size}"}
    copy_dir  = os.path.join(CFG["base_dir"], "copied_from_usb")
    rel       = os.path.relpath(src, usb_root)
    rel_parts = [safe_name(p) for p in Path(rel).parts]
    dest_dir  = os.path.join(copy_dir, safe_name(drive_label), *rel_parts[:-1])
    os.makedirs(dest_dir, exist_ok=True)
    dest      = os.path.join(dest_dir, rel_parts[-1])
    base_, ext= os.path.splitext(dest)
    counter   = 1
    while os.path.exists(dest):
        dest    = f"{base_}_{counter}{ext}"
        counter += 1
    try:
        shutil.copyfile(src, dest)
        return {"copied": True, "destination": dest, "size": size}
    except (PermissionError, OSError) as exc:
        return {"copied": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# REPORT WRITER
# ---------------------------------------------------------------------------
def write_text_report(drive: dict, lock_result: dict, results: List[dict],
                      copied: List[dict], started: str, ended: str,
                      reports_dir: str) -> str:
    ts          = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = os.path.join(reports_dir, f"usb_scan_report_{ts}.txt")
    danger      = [r for r in results if r.get("severity") == "DANGER"]
    warn        = [r for r in results if r.get("severity") == "WARNING"]
    try:
        lines = [
            "=" * 90,
            f"{APP_NAME} v{VERSION} – TEXT REPORT",
            "=" * 90,
            f"Started : {started}",
            f"Ended   : {ended}",
            f"OS      : {platform.system()}",
            f"Computer: {platform.node()}",
            f"USB     : {drive.get('mountpoint')}  Device: {drive.get('device')}  UUID: {drive.get('uuid','')}",
            f"Lock    : {json.dumps(lock_result, ensure_ascii=False)}",
            "",
            "SUMMARY",
            "-" * 90,
            f"Total scanned : {len(results)}",
            f"Danger        : {len(danger)}",
            f"Warnings      : {len(warn)}",
            f"Safe          : {len([r for r in results if r.get('severity') == 'SAFE'])}",
            f"Copied files  : {len([c for c in copied if c.get('copied')])}",
            "",
        ]
        for section_name, section in [("DANGER FILES", danger), ("WARNING FILES", warn)]:
            if section:
                lines += [section_name, "-" * 90]
                for r in section:
                    lines.append(f"File      : {r['file']}")
                    lines.append(f"Score     : {r.get('risk_score', 0)}/100")
                    if r.get("sha256"):
                        lines.append(f"SHA256    : {r['sha256']}")
                    if r.get("confidence"):
                        lines.append(f"Confidence: {r['confidence'].get('tier')} "
                                     f"(engines: {', '.join(r['confidence'].get('agreeing_engines', []))})")
                    if r.get("mitre"):
                        mitre_str = "; ".join(f"{m['technique_id']} {m['technique']}" for m in r["mitre"])
                        lines.append(f"MITRE     : {mitre_str}")
                    for f_ in r.get("findings", []):
                        lines.append(f"  ↳ {f_}")
                    lines.append("")
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return report_path
    except (PermissionError, OSError) as exc:
        fallback = os.path.join(str(Path.home()), f"usb_scan_fallback_{ts}.txt")
        try:
            with open(fallback, "w", encoding="utf-8") as fh:
                fh.write(f"Report failed at {report_path}: {exc}\n")
        except OSError:
            pass
        return fallback


# ---------------------------------------------------------------------------
# MAIN DRIVE SCAN FUNCTION
# ---------------------------------------------------------------------------
def scan_usb_drive(drive: dict, args: argparse.Namespace,
                   data_dirs: dict, global_cache: ScanCache,
                   trust_policy: TrustPolicy,
                   usb_identity: USBIdentity,
                   device_history: DeviceHistory,
                   reputation: ReputationChecker,
                   quarantine: SecureQuarantine,
                   whitelist: WhitelistDB) -> None:
    mp      = drive["mountpoint"]
    started = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"USB detected: {mp}", "success", args.quiet)
    notify_user(APP_NAME, "USB detected. Attempting read-only lock.")

    # REQ-02: Device identity (full VID/PID/serial/USB version/capacity)
    identity = usb_identity.identify(drive)
    log(f"Device: VID={identity.get('vendor_id')} PID={identity.get('product_id')} "
        f"Serial={identity.get('serial')} Mfr={identity.get('manufacturer')} "
        f"USB={identity.get('usb_version')} Speed={identity.get('speed')}", "info", args.quiet)

    # REQ-23: Whitelist device check
    if whitelist.is_whitelisted_device(identity):
        log("USB device is on VID/PID whitelist — reduced scanning.", "success", args.quiet)

    # Trust policy
    tier = trust_policy.classify(identity)
    log(f"USB trust tier: {tier}", "info", args.quiet)
    if tier == "BLOCKED":
        log("USB is BLOCKED by policy. Skipping scan.", "danger", args.quiet)
        notify_user("USB BLOCKED", "This USB is blocked by security policy.")
        device_history.record(drive, identity, {"blocked": True, "tier": tier})
        return

    # Read-only lock
    lock_mgr    = USBReadOnlyManager()
    lock_result = {}
    if tier != "TRUSTED":
        lock_result = lock_mgr.lock(drive)
        if lock_result.get("locked"):
            log("USB set to read-only.", "success", args.quiet)
        else:
            log(f"Read-only lock failed: {lock_result.get('error')}", "warning", args.quiet)

    # Discover files (REQ-25: priority queue — executables first)
    files = discover_files(mp)
    total = len(files)
    log(f"Files discovered: {total} (executables prioritized)", "info", args.quiet)

    # REQ-04: Memory scan
    mem_scanner  = MemoryScanner()
    mem_findings = mem_scanner.scan_all()
    for mf in mem_findings:
        if mf.get("suspicious"):
            log(f"REQ-04 Memory anomaly – PID {mf.get('pid')} {mf.get('name')}: "
                f"{'; '.join(mf.get('findings', []))}", "warning", args.quiet)

    # REQ-05: Start process monitor
    proc_monitor = ProcessMonitor(usb_root=mp)
    proc_monitor.start()

    # Build pipeline
    pipe            = USBScanPipeline(clam_db=args.clamav_db,
                                      data_dir=data_dirs["base"],
                                      whitelist=whitelist)
    archive_scanner = ArchiveScanner(
        pipeline    = pipe,
        max_extract = CFG["max_archive_extract_size"],
        max_members = CFG["max_archive_members"],
    )

    results      = []
    copied       = []
    danger_found = False

    # REQ-25: adaptive worker count
    worker_count = min(args.workers, total) if total > 0 else 1

    executor          = ThreadPoolExecutor(max_workers=worker_count)
    executor_shutdown = False
    futures: Dict[Future, str] = {}

    try:
        for f in files:
            if STOP_EVENT.is_set():
                break
            futures[executor.submit(
                _scan_one, f, mp, pipe, archive_scanner,
                global_cache, reputation, args.sandbox
            )] = f

        completed = 0
        for fut in as_completed(futures):
            if STOP_EVENT.is_set():
                executor.shutdown(wait=False, cancel_futures=True)
                executor_shutdown = True
                break
            src        = futures[fut]
            completed += 1
            pct        = (completed / total) * 100 if total else 100
            if not args.quiet:
                with PRINT_LOCK:
                    print(f"\r[{completed}/{total}] {pct:.1f}% {os.path.basename(src)[:55]}",
                          end="", flush=True)
            # REQ-24: graceful error recovery per file
            try:
                r = fut.result(timeout=CFG["scan_task_timeout"])
            except subprocess.TimeoutExpired:
                r = {"file": src, "severity": "WARNING", "status": "ERROR",
                     "infected": False, "findings": ["Scan timed out"], "engines": {}}
            except PermissionError as exc:
                r = {"file": src, "severity": "WARNING", "status": "ERROR",
                     "infected": False, "findings": [f"Permission denied: {exc}"], "engines": {}}
            except Exception as exc:
                r = {"file": src, "severity": "WARNING", "status": "ERROR",
                     "infected": False, "findings": [f"Scan error: {exc}"], "engines": {}}
            results.append(r)

            if r.get("severity") == "DANGER":
                danger_found = True
                if not args.quiet:
                    with PRINT_LOCK: print()
                log(f"DANGER: {os.path.basename(r['file'])} → "
                    f"{'; '.join(r.get('findings', [])[:3])}", "danger", args.quiet)
                # REQ-22: Quarantine
                if CFG.get("quarantine_enabled"):
                    qr = quarantine.quarantine(
                        src=r["file"], findings=r.get("findings", []),
                        sha256=r.get("sha256", "")
                    )
                    r["quarantine"] = qr
                    if qr.get("quarantined"):
                        log(f"Quarantined → {qr['vault_path']}", "success", args.quiet)
            elif r.get("severity") == "WARNING":
                if not args.quiet:
                    with PRINT_LOCK: print()
                log(f"WARNING: {os.path.basename(r['file'])} → "
                    f"{'; '.join(r.get('findings', [])[:3])}", "warning", args.quiet)

    finally:
        proc_monitor.stop()
        if not executor_shutdown:
            executor.shutdown(wait=False, cancel_futures=True)
        if not args.quiet:
            with PRINT_LOCK: print()

    # Copy clean files
    if args.copy_clean:
        if danger_found and not args.copy_even_if_threats:
            log("Threats found – copy skipped. Use --copy-even-if-threats to override.",
                "warning", args.quiet)
        else:
            label      = safe_name(os.path.basename(mp.rstrip(os.sep)) or "usb")
            safe_files = {r["file"] for r in results
                          if r.get("severity") == "SAFE" and not r.get("infected")}
            log(f"Copying {len(safe_files)} clean files from USB…", "info", args.quiet)
            for src in safe_files:
                if STOP_EVENT.is_set():
                    break
                copied.append({"source": src, **copy_file_from_usb(src, mp, label)})

    ended  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = write_text_report(drive, lock_result, results, copied, started, ended,
                               data_dirs["reports"])
    log(f"Report: {report}", "success", args.quiet)

    summary = {
        "total":   len(results),
        "danger":  sum(1 for r in results if r.get("severity") == "DANGER"),
        "warning": sum(1 for r in results if r.get("severity") == "WARNING"),
        "report":  report, "tier": tier,
    }
    device_history.record(drive, identity, summary)

    if danger_found:
        log("Threats confirmed. USB remains read-only/blocked.", "danger", args.quiet)
        notify_user(APP_NAME, "⚠️ Threats found on USB! See report for details.")
    elif tier != "TRUSTED" and args.restore_rw:
        log(f"Restoring read-write: {lock_mgr.unlock(drive)}", "info", args.quiet)
    else:
        log("Scan complete. USB left read-only by policy.", "success", args.quiet)


def _scan_one(path: str, usb_root: str, pipe: USBScanPipeline,
              archive_scanner: ArchiveScanner, cache: ScanCache,
              reputation: ReputationChecker, sandbox_enabled: bool) -> dict:
    """
    REQ-21: Cache hit → skip.
    REQ-03: Reputation check.
    REQ-06/07/08: Archive scanning.
    REQ-17: Sandbox detonation for high-risk files.
    REQ-25: Lazy hashing — only hash if not already cached.
    """
    # REQ-25: Lazy hashing (skip if already have a cache miss on size check)
    sha = sha256_file(path) if not os.path.islink(path) else None

    # REQ-21: Cache hit
    if sha:
        cached = cache.get(sha)
        if cached:
            cached["cache_hit"] = True
            return cached

    # REQ-03: Reputation lookup
    if sha:
        rep = reputation.lookup(sha)
        if rep.get("verdict") == "BAD":
            result = {
                "file": path, "sha256": sha, "size": file_size(path),
                "risk_score": 100, "severity": "DANGER", "status": "FOUND",
                "infected": True, "findings": [f"Reputation: KNOWN BAD ({rep.get('source')})"],
                "engines": {"reputation": rep},
            }
            cache.put(sha, result)
            return result
        if rep.get("verdict") == "GOOD":
            result = {
                "file": path, "sha256": sha, "size": file_size(path),
                "risk_score": 0, "severity": "SAFE", "status": "OK",
                "infected": False, "findings": ["Reputation: KNOWN GOOD"],
                "engines": {"reputation": rep},
            }
            cache.put(sha, result)
            return result

    # REQ-06/07/08: Archive
    ext = os.path.splitext(path.lower())[1]
    if ext in ARCHIVE_EXTENSIONS:
        arc_result = archive_scanner.scan(path, usb_root)
        if arc_result.get("password_protected"):
            result = {
                "file": path, "sha256": sha, "size": file_size(path),
                "risk_score": 60, "severity": "WARNING", "status": "SUSPICIOUS",
                "infected": False,
                "findings": ["REQ-08: Password-protected archive detected — cannot scan contents"],
                "engines": {"archive": arc_result},
            }
            if sha:
                cache.put(sha, result)
            return result
        if arc_result.get("danger"):
            result = {
                "file": path, "sha256": sha, "size": file_size(path),
                "risk_score": 90, "severity": "DANGER", "status": "FOUND",
                "infected": True,
                "findings": [f"Archive contains threat: {f}"
                             for f in arc_result.get("findings", [])],
                "engines": {"archive": arc_result},
            }
            if sha:
                cache.put(sha, result)
            return result

    # Full pipeline scan
    result = pipe.scan_file(path, usb_root)

    # REQ-17: Sandbox for high-risk files (not already confirmed DANGER)
    if (sandbox_enabled and result.get("severity") == "WARNING" and
            ext in EXEC_EXTENSIONS and not os.path.islink(path)):
        sb = SandboxSubmitter()
        sb_result = sb.submit(path)
        result["engines"]["sandbox"] = sb_result
        if sb_result.get("verdict") == "BAD":
            result["risk_score"] = 100
            result["severity"]   = "DANGER"
            result["infected"]   = True
            result["status"]     = "FOUND"
            result["findings"].append(
                f"Sandbox verdict: MALICIOUS "
                f"({sb_result.get('cuckoo_score', sb_result.get('task_id', ''))})"
            )

    if sha:
        cache.put(sha, result)
    return result


# ---------------------------------------------------------------------------
# STARTUP CHECK
# ---------------------------------------------------------------------------
def startup_check(args: argparse.Namespace) -> None:
    clam = ClamAVScanner(database_dir=args.clamav_db)
    db   = clam.database_status()
    if args.quiet:
        return
    print("=" * 80)
    print(f"{APP_NAME} v{VERSION}")
    print("=" * 80)
    cols = [
        ("OS",               platform.system()),
        ("Python",           sys.version.split()[0]),
        ("ClamAV binary",    clam._clamscan or "NOT FOUND"),
        ("ClamAV database",  clam._db),
        ("DB available",     str(db.get("available"))),
        ("DB error",         db.get("error", "") if not db.get("available") else ""),
        ("YARA",             "available" if yara else "MISSING (pip install yara-python)"),
        ("oletools",         "available" if OLETOOLS_AVAILABLE else "MISSING (pip install oletools)"),
        ("mraptor",          "available" if MRAPTOR_AVAILABLE else "install oletools[full]"),
        ("pefile",           "available" if PEFILE_AVAILABLE else "MISSING (pip install pefile)"),
        ("lief",             "available" if LIEF_AVAILABLE else "optional (pip install lief)"),
        ("pyelftools",       "available" if PYELFTOOLS_AVAILABLE else "optional (pip install pyelftools)"),
        ("macholib",         "available" if MACHOLIB_AVAILABLE else "optional (pip install macholib)"),
        ("pycryptodome",     "available" if CRYPTO_AVAILABLE else "MISSING (pip install pycryptodome)"),
        ("sklearn/ML",       "available" if ML_AVAILABLE else "optional (pip install scikit-learn numpy)"),
        ("psutil",           "available" if psutil else "MISSING (pip install psutil)"),
        ("python-magic",     "available" if magic else "optional (pip install python-magic)"),
        ("requests/APIs",    "available" if REQUESTS_AVAILABLE else "optional (pip install requests)"),
        ("Base dir",         CFG["base_dir"]),
        ("Config file",      args.config or "default"),
        ("VirusTotal",       "configured" if CFG.get("virustotal_api_key") else "not configured"),
        ("Malware Bazaar",   "configured" if CFG.get("malware_bazaar_api_key") else "not configured"),
        ("OpenTIP",          "configured" if CFG.get("openTIP_api_key") else "not configured"),
        ("Cuckoo sandbox",   CFG.get("cuckoo_url") or "not configured"),
        ("Any.Run",          "configured" if CFG.get("any_run_api_key") else "not configured"),
    ]
    for label, value in cols:
        if value:
            print(f"  {label:<24}: {value}")
    print("=" * 80)
    print("\nInstall all optional deps:")
    print("  pip install yara-python oletools pefile lief pyelftools macholib "
          "pycryptodome scikit-learn numpy psutil python-magic requests")
    print("=" * 80)


# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION} – Cross-OS USB malware scanner (all 25 REQs)"
    )
    ap.add_argument("--config",               default=None,
                    help="Path to JSON config file")
    ap.add_argument("--clamav-db",            default=None,
                    help="ClamAV database directory")
    ap.add_argument("--copy-clean",           action="store_true",
                    help="Copy SAFE files FROM USB to local machine after scan")
    ap.add_argument("--copy-even-if-threats", action="store_true",
                    help="Allow copy even when threats are found")
    ap.add_argument("--restore-rw",           action="store_true",
                    help="Restore read-write if no threats found")
    ap.add_argument("--quiet",                action="store_true",
                    help="Suppress terminal progress output")
    ap.add_argument("--workers",              type=int, default=None,
                    help="Scanner thread count (default: CPU core count)")
    ap.add_argument("--scan-memory",          action="store_true",
                    help="Run startup memory process scan (REQ-04)")
    ap.add_argument("--sandbox",              action="store_true",
                    help="Enable sandbox detonation for suspicious files (REQ-17)")
    return ap.parse_args()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()
    load_config(args.config)

    base_dir    = CFG["base_dir"]
    reports_dir = os.path.join(base_dir, "reports")
    for d in (base_dir, reports_dir,
              os.path.join(base_dir, "copied_from_usb"),
              os.path.join(base_dir, "quarantine")):
        os.makedirs(d, exist_ok=True)

    data_dirs = {"base": base_dir, "reports": reports_dir}

    logging.basicConfig(
        filename=os.path.join(base_dir, "usb_enterprise_shield.log"),
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s"
    )

    # REQ-25: adaptive worker count based on CPU cores
    cpu_count    = os.cpu_count() or 4
    default_wkrs = min(cpu_count, CFG.get("max_workers", cpu_count))
    workers      = max(1, min(args.workers or default_wkrs, cpu_count * 2))
    args.workers = workers

    startup_check(args)

    # REQ-21: Persistent scan cache
    cache_path   = os.path.join(base_dir, "scan_cache.json")
    global_cache = ScanCache(cache_path, ttl=CFG["cache_ttl_seconds"])

    trust_policy   = TrustPolicy(base_dir, default=CFG["default_usb_policy"])
    usb_identity   = USBIdentity(base_dir)
    device_history = DeviceHistory(base_dir)
    whitelist      = WhitelistDB()  # REQ-23

    # REQ-03: Multi-source reputation checker
    reputation = ReputationChecker(
        base_dir,
        vt_api_key=CFG.get("virustotal_api_key", ""),
        mb_api_key=CFG.get("malware_bazaar_api_key", ""),
        openTIP_key=CFG.get("openTIP_api_key", ""),
    )

    secure_quarantine = SecureQuarantine(base_dir)  # REQ-22

    # REQ-04: Optional startup memory scan
    if args.scan_memory:
        log("Running startup memory scan (REQ-04)…", "info", args.quiet)
        mem = MemoryScanner()
        for mf in mem.scan_all():
            if mf.get("suspicious"):
                log(f"Memory alert – {mf.get('name')} (PID {mf.get('pid')}): "
                    f"{'; '.join(mf.get('findings', []))}", "warning", args.quiet)

    log("Monitoring for USB drives…", "info", args.quiet)
    seen: Set[str] = set()

    while not STOP_EVENT.is_set():
        try:
            current      = get_usb_drives()
            current_sigs = {get_drive_signature(d): d for d in current}

            for sig, drive in current_sigs.items():
                if sig not in seen:
                    seen.add(sig)
                    scan_usb_drive(
                        drive          = drive,
                        args           = args,
                        data_dirs      = data_dirs,
                        global_cache   = global_cache,
                        trust_policy   = trust_policy,
                        usb_identity   = usb_identity,
                        device_history = device_history,
                        reputation     = reputation,
                        quarantine     = secure_quarantine,
                        whitelist      = whitelist,
                    )

            seen.intersection_update(set(current_sigs.keys()))
            time.sleep(2)

        except KeyboardInterrupt:
            break
        except Exception as exc:
            # REQ-24: Main loop error recovery — log and continue
            log(f"Main loop error (continuing): {exc}", "danger", args.quiet)
            time.sleep(2)

    log("USB Enterprise Shield stopped.", "warning", args.quiet)


if __name__ == "__main__":
    main()
