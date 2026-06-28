# USB Enterprise Shield

**Cross-platform, enterprise-grade USB malware scanner for Linux, macOS, and Windows.**

USB Enterprise Shield monitors USB drives the moment they connect, runs them through a multi-engine detection pipeline, and either quarantines threats or copies clean files — all with zero manual intervention.

---

## Features at a Glance 

| Category | Capability |
|---|---|
| **Detection engines** | ClamAV, YARA (weighted categories), ML heuristics (RandomForest), behavioural correlation |
| **File types** | PE/ELF/Mach-O binaries, Office macros, PDFs, HTML, archives (nested, 4 levels), scripts |
| **Threat response** | AES-256-GCM quarantine, optional sandbox detonation (Cuckoo / Any.Run), process termination |
| **Reputation** | VirusTotal, MalwareBazaar, OpenTIP, local SQLite DB, fuzzy-hash (TLSH) variant matching |
| **Reports** | TXT, JSON, HTML (styled), CSV per scan; optional PDF (requires reportlab) |
| **Persistence** | SQLite scan cache (signature-version-aware), SQLite device history, HMAC-protected config |
| **Privacy** | `offline_only` mode — no hash or file leaves the host unless you explicitly configure an API |

---

## Requirements

### Core (scanner won't start without these)

```
pip install psutil pycryptodome
```

ClamAV must also be installed at the OS level:

| Platform | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install clamav clamav-daemon && sudo freshclam` |
| macOS (Homebrew) | `brew install clamav && freshclam` |
| Windows | Download the ClamAV installer from https://www.clamav.net |

### Optional (enable additional detection layers)

```
pip install yara-python oletools pefile lief pyelftools macholib \
            scikit-learn numpy python-magic requests tlsh reportlab
```

Run `--check-only` at any time to see which components are active on your system.

---

## Installation

```bash
git clone https://github.com/your-org/usb-enterprise-shield.git
cd usb-enterprise-shield
pip install psutil pycryptodome          # core
pip install -r requirements.txt          # all optional deps
```

No build step is required — the scanner is a single Python file.

---

## Quick Start

```bash
# Monitor loop — waits for a USB drive and scans it automatically
sudo python3 usb_enterprise_shield_v01.py

# Check dependency status and exit
sudo python3 usb_enterprise_shield_v01.py --check-only

# Copy clean files from the USB to your machine after scanning
sudo python3 usb_enterprise_shield_v01.py --copy-clean

# Enable sandbox detonation for suspicious executables
sudo python3 usb_enterprise_shield_v01.py --sandbox

# Run a startup memory scan before entering monitor mode
sudo python3 usb_enterprise_shield_v01.py --scan-memory

# Use a custom config file
sudo python3 usb_enterprise_shield_v01.py --config /etc/usb_shield/config.json

# Train the ML model on your own labelled dataset
sudo python3 usb_enterprise_shield_v01.py --train-model /path/to/dataset_dir
```

---

## CLI Reference

| Flag | Description |
|---|---|
| `--config PATH` | JSON config file (overrides built-in defaults) |
| `--clamav-db DIR` | Path to ClamAV virus database directory |
| `--copy-clean` | Copy SAFE-rated files from USB to local machine |
| `--copy-even-if-threats` | Copy files even when threats are found (use with caution) |
| `--restore-rw` | Restore read-write access to USB when no threats are found |
| `--quiet` | Suppress terminal progress output |
| `--workers N` | Scanner thread count (default: CPU core count) |
| `--scan-memory` | Run startup memory/process scan |
| `--sandbox` | Enable sandbox detonation for WARNING-severity executables |
| `--check-only` | Print dependency table and exit |
| `--train-model DIR` | Train RandomForest model from a directory of labelled samples |

---

## Configuration

On first run, the scanner uses built-in defaults. To customise behaviour, create a `config.json`:

```json
{
  "base_dir": "/var/lib/usb_shield",
  "score_danger": 85,
  "score_warning": 45,
  "quarantine_enabled": true,
  "quarantine_retention_days": 90,
  "cache_ttl_seconds": 3600,
  "reputation_mode": "offline_only",
  "default_usb_policy": "READ_ONLY",
  "virustotal_api_key": "",
  "malware_bazaar_api_key": "",
  "cuckoo_url": "",
  "trusted_publishers": [
    "Microsoft Corporation", "Apple Inc.", "Google LLC"
  ]
}
```

The config file is HMAC-protected on write and verified on load — any tampering raises an error rather than silently loading a poisoned config.

### Reputation privacy modes

| Mode | Behaviour |
|---|---|
| `offline_only` | **Default.** Nothing leaves the host. Local DB and heuristics only. |
| `hash_lookup` | Sends SHA-256 hashes to configured APIs (no file bytes). |
| `upload_samples` | Full sample upload to sandbox / cloud AV (explicit opt-in required). |

---

## Data Directory Layout

All runtime data is written to `~/USB_Enterprise_Shield_Data/` (configurable via `base_dir`):

```
USB_Enterprise_Shield_Data/
├── reports/              # TXT, JSON, HTML, CSV scan reports
├── quarantine/           # AES-256-GCM encrypted threat vault
│   ├── *.quar            # Encrypted file
│   └── *.meta.json       # Metadata (original path, SHA-256, findings)
├── scan_cache.sqlite      # SQLite scan-result cache
├── device_history.sqlite  # All USB device insertions (indexed by serial)
├── trusted_devices.json   # USB trust database
├── quarantine_key.bin     # AES-256 quarantine key (chmod 600)
└── usb_enterprise_shield.log
```

---

## Detection Pipeline

When a USB drive is detected, each file flows through the following engines in priority order (executables first, media last):

```
File
 │
 ├─► Whitelist check (SHA-256 / publisher / path)        → skip if trusted
 ├─► Reputation check (local DB + optional cloud)        → fast-path if known
 ├─► ClamAV signature scan                               → score +100 if hit
 ├─► YARA rules (weighted by category)                   → score +15..+100
 ├─► Digital signature verification                      → score −30..+60
 ├─► MIME type / extension mismatch                      → score +80
 ├─► Windowed entropy analysis (4 windows)               → packed-section flag
 ├─► PE / ELF / Mach-O binary analysis                   → score 0..+80
 ├─► Office macro analysis (olevba + mraptor)            → score 0..+100
 ├─► PDF stream analysis                                 → score 0..+100
 ├─► HTML / JS obfuscation analysis                      → score 0..+100
 ├─► Network IOC extraction (IPs, domains, C2)           → score 0..+100
 ├─► ML heuristic scorer (RandomForest or fallback)      → ml_score 0..100
 ├─► Behavioural correlation engine (combo bonuses)      → adjusts final score
 └─► Sandbox detonation (optional, WARNING files only)   → verdict CLEAN/BAD
```

**Final risk score** is clamped to [0, 100]:

- **≥ 85** → `DANGER` — quarantined, process terminated, user notified
- **45–84** → `WARNING` — flagged, optionally sandbox-detonated
- **< 45** → `SAFE` — optionally copied to local machine

---

## Quarantine

Quarantined files are encrypted with AES-256-GCM (streaming, no full-RAM load) and stored in the vault directory with a companion `.meta.json`. The encryption key is generated once and stored at `quarantine_key.bin` with `chmod 600`.

To restore a quarantined file:

```python
from usb_enterprise_shield_v01 import SecureQuarantine
q = SecureQuarantine("/path/to/USB_Enterprise_Shield_Data")
result = q.restore("/path/to/quarantine/20240101_120000_evil.exe.quar",
                   dest_path="/tmp/restored_evil.exe")
```

Quarantine items older than `quarantine_retention_days` (default 90) are securely wiped (overwrite + delete) automatically on startup.

---

## ML Model Training

```bash
# Dataset directory must contain two sub-folders: malware/ and benign/
sudo python3 usb_enterprise_shield_v01.py --train-model /path/to/dataset

# Then load the model at runtime
# In config.json: "ml_model_path": "/path/to/model.joblib"
```

Training outputs precision, recall, ROC-AUC, and FPR metrics so model quality is measurable rather than assumed.

---

## YARA Rules

Place your `.yar` / `.yara` rule files in any directory and configure the path:

```json
{ "yara_rules_path": "/etc/usb_shield/rules" }
```

Rules are weighted by the `yara_category_weights` config key. Per-category score caps prevent double-counting within the same category.

---

## Troubleshooting

**`sqlite3.DatabaseError: file is not a database`**
A legacy JSON cache file exists at the scan cache path. Delete it:
```bash
rm ~/USB_Enterprise_Shield_Data/scan_cache.json
```
The scanner will create a fresh SQLite database on next run.

**ClamAV not found**
Make sure `clamscan` is on your `$PATH` and the database is up to date (`freshclam`).

**`pycryptodome` missing — quarantine disabled**
Quarantine requires AES-256-GCM and will refuse to fall back to a weaker cipher. Install it:
```bash
pip install pycryptodome
```

**Permission denied on macOS/Linux**
The scanner needs read access to USB mount points and (optionally) process visibility. Run with `sudo`.

---

## Security Notes

- USB device identity (VID/PID/serial) is software-fingerprinted. A programmable USB device can fake these fields. The fingerprint detects *inconsistency* (same serial, different VID/PID on re-insertion) but is not a cryptographic root of trust.
- In `offline_only` mode, no file bytes or hashes leave the host.
- The config file is HMAC-protected. An attacker who gains write access to `config.json` cannot silently add a trusted serial without the secret being rotated.

---

## License

See [LICENSE](LICENSE).

---

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Run the dependency check before committing: `python3 usb_enterprise_shield_v01.py --check-only`
4. Open a pull request describing what the change fixes or adds.
