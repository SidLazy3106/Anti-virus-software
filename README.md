# Sentinel

A Python prototype of a Windows security suite: file scanner, real-time protection, browser guard, and system audit.
Built for learning and group projects. **It is not a replacement for Microsoft Defender or a commercial product.**

## What's inside

| Module | File | What it does |
|---|---|---|
| Scan engine | `sentinel/scanner.py` | SHA-256 blocklist, EICAR, disguised executables, double extensions, entropy, PE section/import heuristics, script patterns, optional YARA |
| Quarantine | `sentinel/quarantine.py` | Moves files out of reach (XOR-obfuscated, restorable). Obfuscation, not encryption |
| Real-time | `sentinel/monitor.py` | Folder watcher that scans new/changed files, ransomware canary files and change-rate alerts, suspicious process chains (Office spawning PowerShell, etc.) |
| System audit | `sentinel/sysaudit.py` | Firewall, Defender, UAC, RDP, SMBv1, startup entries, scheduled tasks, risky listening ports, script hosts with internet connections. Produces a 0-100 score |
| URL analysis | `sentinel/webguard.py` | Look-alike domains, punycode, raw IPs, `@` tricks, risky TLDs, brand abuse, keywords |
| Browser guard | `browser_extension/` | Chrome/Edge MV3 extension using the same URL logic (verified identical results), risky-download warnings, suspicious login-page banner |
| Threat feeds | `sentinel/updater.py` | Downloads public hash/domain blocklists |
| UI | `sentinel/gui.py`, `main.py` | Tkinter GUI plus a CLI |

## Setup (Windows)

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python main.py            # GUI
```

CLI: `python main.py scan C:\Users\you\Downloads [--quarantine]`, `audit`, `url <url>`, `monitor <folders> [--auto-quarantine] [--canaries]`, `update`.
Run the terminal as Administrator for the fullest audit and network view.

## Browser extension

Chrome or Edge, then `chrome://extensions`, turn on Developer mode, **Load unpacked**, and pick the `browser_extension` folder.
High-risk URLs get a block page, medium-risk ones get a badge, and password forms on risky pages get a red banner.

## Tests

```
python -m unittest discover -s tests -v
```

## Safe testing

Use the harmless EICAR test string, or build it at runtime as in `tests/test_sentinel.py`. If you ever test with real malware,
do it only in an isolated VM with networking disabled and snapshots. Never on your main machine.

## Known limitations (be upfront about these in your report)

- User-mode only: no kernel driver, so it cannot block execution, only detect and react. A minifilter driver is the real next step.
- Heuristics cause false positives (packed installers, .NET apps, cracks) and miss novel malware. No Authenticode/signature check yet.
- Quarantine is obfuscated, not encrypted (key sits in `index.json`).
- The URL brand list and `OFFICIAL` domain set are small. Swap in a top-sites list (e.g. Tranco) for production use.
- Registered-domain parsing is simplified. Use the Public Suffix List for production use.
- The extension cannot hand downloaded files to the desktop scanner yet. That needs Native Messaging.
- Threat feeds change terms and access rules (some abuse.ch endpoints may need a free key via `SENTINEL_FEED_KEY`). Check before relying on them.
- Windows audit checks were written against documented APIs/registry keys but should be verified on your own machines.

## Suggested group split

1. Scan engine + signatures/YARA rules
2. Real-time monitor + ransomware guard
3. System audit + hardening advice
4. Browser extension + native messaging
5. GUI, packaging (PyInstaller), documentation and testing

## Roadmap

Authenticode verification, Native Messaging bridge, ETW-based process telemetry, encrypted quarantine, PyInstaller installer with signed updates,
scan scheduling, and a detection-rate/false-positive benchmark against a clean-file corpus.
