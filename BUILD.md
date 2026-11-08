# Building, installing and releasing X-Secure

## Run from source (development)

```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements-dev.txt
python main.py                # opens the app
python -m pytest              # tests
```

## Build the Windows release

```
pip install pyinstaller       # once
python tools/build_release.py
```

The script runs the tests, makes the icon and the Windows version resource, runs PyInstaller (`xsecure.spec`), then
**starts the built executables** to check them, and finally packages the result:

| Output | What it is |
|---|---|
| `dist\X-Secure\X-Secure.exe` | the windowed app (no console) |
| `dist\X-Secure\x-secure-cli.exe` | the command line, also the browser-bridge host |
| `release\X-Secure-<version>-win64-portable.zip` | the whole app as one portable zip (no install needed) |
| `release\X-Secure-<version>-setup.exe` | the installer, **only if Inno Setup 6 is installed** |
| `release\release.json` | version, file name, size and SHA-256 (the website's download button reads this) |

`--skip-tests` skips the unit tests (not for real releases); `--no-build` only repackages an existing `dist\X-Secure`.

The installer (`installer\xsecure.iss`) installs per-user without administrator rights, lets the user choose the
folder and an optional desktop shortcut, and removes the scheduled-scan task on uninstall. Settings, quarantine and
logs live in `%USERPROFILE%\.x-secure` and are kept on purpose when the app is uninstalled.

## Install on another laptop

Portable: unzip `X-Secure-<version>-win64-portable.zip` anywhere and run `X-Secure\X-Secure.exe`. Nothing else
(Python, pip, the repository) is needed. Installer: run `X-Secure-<version>-setup.exe`.

The build is **not code-signed**, so Windows SmartScreen may show "Windows protected your PC" on first run
(More info, Run anyway). Compare the file's SHA-256 with `release.json` / the website before running it:
`Get-FileHash .\X-Secure-1.0.0-win64-portable.zip -Algorithm SHA256`.

## Update flow

The app does not update itself. To update, download the new zip or installer and install over the old one; user data in
`%USERPROFILE%\.x-secure` is untouched. (Threat-feed data is separate: `x-secure update`.)

## The website

`docs\` is a static site (GitHub Pages friendly). Open it with any static server, for example
`python -m http.server 8000 --directory docs`, then browse to http://localhost:8000. `docs\release.json` and
`docs\downloads\` are written by the release script; the download button only shows a real link when that file exists.
`docs\url_rules.js` and `docs\analyzer.js` are generated: run `python tools/sync_extension_rules.py`.

## Releasing a new version

1. Change `VERSION` in `sentinel/config.py` and `version` in `pyproject.toml` (a test checks they match).
2. `python tools/build_release.py`
3. Publish `release\*` as a GitHub Release and commit the updated `docs\release.json`.
