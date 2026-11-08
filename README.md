# X-Secure

A Python prototype of a Windows security suite: file scanner, real-time protection, browser guard with a desktop
scanning bridge, system audit and a safe PC optimizer.
Built for learning and group projects. **It is not a replacement for Microsoft Defender or a commercial product.**

## What's inside

| Module | File | What it does |
|---|---|---|
| Scan engine | `sentinel/scanner.py` | SHA-256 blocklist, EICAR, disguised executables, double extensions, entropy, PE section/import heuristics, script patterns (PowerShell/VBS/JS, LOLBins, AMSI/Defender tampering, **download-and-run cradles**; UTF-16 scripts decoded; `-EncodedCommand` payloads decoded and inspected), padded-executable detection, **archive inspection** (hidden programs, zip bombs, password-protected), **Office macro and remote-template detection** (docx/xlsm and legacy .doc/.xls), ransom-note names, **hidden NTFS alternate data streams**, **hash allowlist** (`python main.py allow <file>`), optional YARA |
| Signature check | `sentinel/authenticode.py` | Verifies a program's digital signature with Windows' own `WinVerifyTrust`, offline (no revocation or network lookups). A valid signature lowers *program-structure* heuristics only (packers, entropy, imports, program-named-like-an-image); it never excuses a double extension, a script, ransomware signs or a known-bad hash |
| Alternate data streams | `sentinel/ads.py` | Lists hidden streams (`notes.txt:payload.exe`) with `FindFirstStreamW` and scans them; the normal "downloaded from the internet" marker streams are ignored |
| Scan orchestration | `sentinel/engine.py` | **Quick scan** (high-risk folders) and **Full PC scan** (every fixed drive, high-risk folders first), parallel worker processes at below-normal priority, SQLite cache so repeat scans skip unchanged files (invalidated when signatures, rules, allowlist or detection code change, and after 7 days), never follows junctions/symlinks, skips OneDrive online-only files instead of downloading them |
| Scheduled scans | `sentinel/schedule.py` | Daily or weekly scans through Windows Task Scheduler (your account only, no admin, no console window). The result is saved and shown in the app; a message appears only if something was flagged; nothing is quarantined automatically |
| Logging | `sentinel/logger.py` | Rotating log of detections and alerts in `~/.x-secure/x-secure.log` |
| Quarantine | `sentinel/quarantine.py` | Moves files out of reach and **encrypts** them with Windows DPAPI (AES-256 with integrity check, keyed to your Windows account; no key is stored in the quarantine folder). Each file is bound to its quarantine id, so tampered or swapped files refuse to restore. Items from the older XOR format still restore |
| Real-time | `sentinel/monitor.py` | Folder watcher that scans new/changed files, ransomware canary files, change-rate alerts, **ransomware file extensions and ransom notes**, suspicious process chains (Office spawning PowerShell, etc.), and **scans programs launched from Temp/Downloads** |
| System audit | `sentinel/sysaudit.py` | Firewall, Defender, **Defender exclusions**, UAC, RDP, SMBv1, startup entries and **Startup folders**, scheduled tasks, **WMI persistence**, **registry hijacks (IFEO, AppInit_DLLs, Winlogon)**, **unquoted service paths**, **hosts-file tampering**, risky listening ports, script hosts with internet connections. Produces a 0-100 score |
| URL analysis | `sentinel/webguard.py` | Look-alike domains, punycode (Unicode domains converted like a browser), raw and disguised (decimal/hex/octal) IPs, phishing on shared hosting (S3, web.app, github.io...), `@` tricks, risky TLDs, brand abuse, keywords, the downloaded malicious-domain list, and correct registered domains for every country TLD via the **Public Suffix List** |
| Threat feeds | `sentinel/updater.py` | `python main.py update` downloads live lists: URLhaus malware domains (via the malware-filter mirror) and Phishing Army phishing domains (about 160k domains together), plus the Public Suffix List. Each feed is stored separately, so one failing feed never wipes another, and an error page is never accepted as a list. MalwareBazaar file hashes need a free abuse.ch Auth-Key (set `XSECURE_FEED_KEY`); without one that feed is reported as skipped |
| Browser guard | `browser_extension/` | Chrome/Edge MV3 extension using the same URL logic (identical results enforced by a unit test that runs the JS in Node), risky-download warnings, suspicious login-page banner, and the **desktop scanning bridge** below |
| Desktop bridge | `sentinel/nativehost.py` | Native Messaging host: the extension sends every finished download to the desktop scanner and warns you if it is flagged. The host only reads files; it never opens, runs, moves or deletes anything |
| PC optimizer | `sentinel/optimizer.py`, `sentinel/hardware.py` | Read-only, parallel, cancellable **Quick / Standard / Deep** scans with partial results as each part finishes. Detects your real hardware (CPU, GPU and video memory, RAM, storage type and health, laptop or desktop, battery, refresh rate), cached locally and re-detected only when it changes. Recommendations sit in a collapsible 8-category accordion; each shows the issue, why it matters, benefit, risk, affected component, side effects, original setting and rollback, and nothing is applied without approval. Gaming / Balanced / Workspace / Eco switch the Windows power plan (including built-in plans Windows hides from its own Settings) with an animated, cancellable transition that reports success only after Windows confirms it, and **Restore** puts every change back. Never closes processes, never touches services, security features, the pagefile or boot settings. Temp cleanup is the one change that cannot be undone and is labeled as such |
| Performance Analytics | `sentinel/analytics.py` | Opt-in (off by default) real measurements of this PC per mode (CPU, RAM, process count, disk throughput, timer latency) with sample count, duration and run-to-run variation, compared only across runs on the same hardware. FPS, frame time and power draw show "Not available" because Windows does not expose them to normal apps. No public benchmark data is bundled, so none is shown |
| Benchmark | `sentinel/benchmark.py` | `python main.py benchmark` measures the false-positive rate on clean files and checks every detection technique against harmless synthetic samples |
| UI | `sentinel/gui.py`, `sentinel/ui_kit.py`, `sentinel/aa.py`, `sentinel/mode_art.py` | Tkinter app, DPI-aware (sharp, never blurry), with antialiased cards, rings and graphs (drawn by Pillow at 3-4x and scaled down), eased scrolling, keyboard navigation (Tab, Enter/Space, visible focus), a dark rounded-card design, a protection ring with one clear next step, plain-English wording and color-coded "why it was flagged" results |

## Setup (Windows)

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python main.py            # opens the app
python main.py update     # download the threat feeds (recommended once a day)
```

Run the terminal as Administrator for the fullest audit and network view (everything else works without it).

## Command line

| Command | What it does |
|---|---|
| `scan <path>`, `quickscan`, `fullscan` | Scan. Options: `--quarantine`, `--workers N`, `--no-cache` |
| `audit` | Security health check with a 0-100 score |
| `url <url>` | Check a link |
| `monitor <folders> [--auto-quarantine] [--canaries]` | Real-time protection in the terminal |
| `update` | Download threat feeds and the Public Suffix List |
| `allow <file or sha256>` | Trust a file so it is no longer flagged |
| `schedule set --at 13:00 [--weekly MON] [--full]`, `schedule show`, `schedule run`, `schedule off` | Automatic scans |
| `nativehost install --extension-id <id>`, `nativehost status`, `nativehost uninstall` | Browser desktop bridge |
| `benchmark [folders] [--limit N]` | False-positive and detection benchmark |

## Browser extension

1. Chrome or Edge: open `chrome://extensions` (or `edge://extensions`), turn on **Developer mode**, click **Load unpacked** and pick the `browser_extension` folder.
2. High-risk URLs get a block page, medium-risk ones get a badge, and password forms on risky pages get a red banner.
3. **Desktop bridge (optional):** copy the extension's ID from the extensions page, then run
   `python main.py nativehost install --extension-id <that id>` and restart the browser.
   From then on every finished download is scanned by the desktop engine and you get a notification if it is flagged.
   Use `--extension-id` twice to allow both a Chrome and an Edge copy. `nativehost uninstall` removes it again.

## Scheduled scans

In the app: **Scan** page, *Automatic scan* row, type a time and press **Scan daily**. Or from the command line:
`python main.py schedule set --at 13:00` (add `--weekly SUN` or `--full` as needed), and `schedule off` to remove it.
The task is created for your Windows account only and can also be seen in Task Scheduler under *X-Secure*.

## Building a standalone app

```
pip install pyinstaller
py -m PyInstaller --noconfirm --clean xsecure.spec
```

This produces `dist\X-Secure\` (about 50 MB): `X-Secure.exe` (the app, also used by scheduled scans) and
`x-secure-cli.exe` (command line, also used by the browser bridge). Copy or zip the whole folder as one unit; no
Python installation is needed on the target PC. The build is not code-signed (see limitations).

## Project website

`docs/` is a ready-to-publish portfolio page: screenshots, the measured results, a live link checker that runs the
extension's own JavaScript in the visitor's browser, and an honest limitations section. It has no build step and no
external dependencies (open `docs/index.html` to preview it).

To publish it free on GitHub Pages: push the repo, then **Settings -> Pages -> Build and deployment -> Deploy from a
branch -> `main` / `/docs`**. The site appears at `https://<your-username>.github.io/<repo-name>/`.
Then set `REPO_URL` (and `RELEASE_URL`, once you attach `dist\X-Secure` zipped as a GitHub Release) at the top of the
script in `docs/index.html`; the two buttons stay hidden until those are filled in.

If you change `browser_extension/analyzer.js`, copy it to `docs/analyzer.js` (a test checks they match).
Screenshots in `docs/img/` show sample scan data on the Home and Scan screens; the page says so.

## Tests

```
python -m unittest discover -s tests -v
```

98 tests. They clean up after themselves, and anything that would change the system runs against a scratch
registry key, a scratch folder or a simulated Task Scheduler, never against your real settings.

## Measured results (this development PC, November 2026)

| Check | Result |
|---|---|
| False positives, `benchmark` on 20,000 clean files (System32 + Program Files, no cache) | **0 flagged (0.000%)**, 265 s using all cores |
| Detection of harmless synthetic samples (one per technique) | 10/10 after fixing the download-cradle gap the benchmark found (it was 8/10) |
| Real quick scan of the user profile, Temp, Downloads, AppData, ProgramData | 203,708 files in 9.3 min (first run; repeat runs reuse the cache) |
| Threat feeds | 162,903 live malicious and phishing domains, Public Suffix List with 10,406 rules |
| Power plans | All four modes switched, verified with `powercfg` and restored on real hardware |

Numbers on other machines will differ. Re-run `python main.py benchmark` on yours.

## Safe testing

Use the harmless EICAR test string, or build it at runtime as in `tests/test_sentinel.py`. The benchmark's samples
are harmless by construction. If you ever test with real malware, do it only in an isolated VM with networking
disabled and snapshots. Never on your main machine.

## Known limitations (be upfront about these in your report)

- **User-mode only:** there is no kernel driver, so X-Secure can detect and react but cannot block a program before it runs. A minifilter driver (C, driver signing) is the real next step.
- **No SYSTEM service:** everything in `~/.x-secure` (allowlist, signatures, cache, quarantine index) is writable by any program running as you, and DPAPI-encrypted quarantine can be decrypted by any program running as you. Fixing both needs a service running as SYSTEM.
- **Heuristics** still miss novel malware and can flag unusual but legitimate software (unsigned tools, cracks, auto-clickers). Signed programs are judged more leniently, but signed tools can still be abused.
- **Scan cache:** it trusts file size and modified time for up to 7 days. Malware that rewrites a file with the same size and restores its timestamp is missed until then; use `--no-cache` for full re-verification.
- **Full scan coverage:** it skips `C:\Windows\WinSxS` (Microsoft-signed component store) and OneDrive online-only files.
- **URL checks:** the brand list and `OFFICIAL` domain set are small; a top-sites list (e.g. Tranco) would cut false positives further. The browser extension still uses the simplified domain parsing (only the desktop app uses the Public Suffix List).
- **Threat feeds** change terms and access rules (abuse.ch retired its keyless export URLs; the hash feed now needs `XSECURE_FEED_KEY`). Phishing Army is CC BY-NC 4.0 (non-commercial use only).
- **Optimizer:** it only changes the Windows power plan, per-user startup switches and old temp files. It cannot tune CPU/GPU clocks, close apps for you, or read temperatures, and it makes no claim about FPS or power draw it has not measured. Analytics measures whatever the PC is doing at that moment, so compare modes under a similar workload.
- **Packaging:** the PyInstaller build and the extension are not code-signed, so Windows SmartScreen may warn on first run, and updates are not signed.
- **Audit checks** were written against documented APIs and registry keys but should be verified on your own machines.

## Suggested group split

1. Scan engine, signatures/YARA rules, Authenticode and ADS
2. Real-time monitor + ransomware guard
3. System audit + hardening advice
4. Browser extension + native messaging bridge
5. GUI, optimizer, packaging (PyInstaller), documentation and testing

## Roadmap

Kernel minifilter driver for pre-execution blocking; a SYSTEM service to protect the data folder and quarantine
keys; ETW-based process telemetry; code-signed builds with signed updates; Public Suffix List and a top-sites list
in the browser extension too.
