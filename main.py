"""X-Secure entry point.  python main.py [gui|scan|quickscan|fullscan|audit|url|monitor|update|allow|schedule|nativehost]"""
import argparse
import multiprocessing
import sys
import time


def _add_scan_options(p):
    p.add_argument("--quarantine", action="store_true", help="quarantine malicious files")
    p.add_argument("--workers", type=int, default=None, help="parallel scan processes (default: CPU cores - 1)")
    p.add_argument("--no-cache", action="store_true", help="rescan every file, ignoring earlier clean results")
    p.add_argument("--scheduled", action="store_true",
                   help="unattended run (used by the scheduled task): save the result and alert only if something is found")


def _run_scan(roots, exclude, a) -> int:
    from sentinel import quarantine
    from sentinel.engine import ScanEngine
    from sentinel.scanner import MALICIOUS, SUSPICIOUS
    eng = ScanEngine(workers=a.workers, use_cache=not a.no_cache)
    print(f"Scanning with {eng.workers} worker(s): {', '.join(map(str, roots))}", flush=True)
    last = time.time()
    flagged = []
    try:
        for r in eng.scan(roots, exclude):
            if r.verdict in (SUSPICIOUS, MALICIOUS):
                flagged.append({"path": r.path, "verdict": r.verdict, "score": r.score, "reasons": r.reasons[:4]})
                print(f"{r.verdict.upper():10} {r.score:3}  {r.path}", flush=True)
                for why in r.reasons:
                    print(f"             - {why}")
                if a.quarantine and r.verdict == MALICIOUS:
                    try:
                        quarantine.quarantine_file(r.path, "; ".join(r.reasons), r.sha256)
                        print("             > quarantined")
                    except OSError as e:  # file in use / access denied: keep scanning
                        print(f"             > quarantine failed: {e}")
            if time.time() - last > 5:
                last = time.time()
                print(f"  ... {eng.stats.files} files checked", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("\nScan cancelled.")
    s = eng.stats
    print(f"\n{s.files} files checked ({s.cached} unchanged, answered from cache) in {s.elapsed:.1f}s, "
          f"{s.threats} flagged")
    if s.errors or s.dirs_denied or s.skipped:
        print(f"{s.errors} unreadable file(s), {s.dirs_denied} folder(s) without access, "
              f"{s.skipped} skipped (cloud-only or locked system files). Run as Administrator for more coverage.")
    if getattr(a, "scheduled", False):
        from sentinel import schedule
        schedule.save_result(getattr(a, "cmd", "scan"), s, flagged)
        schedule.notify(s.threats)
    return 1 if s.threats else 0


def _safe_console():
    """Piped/redirected output uses the ANSI code page on Windows, which garbles '—' and can crash on file names
    with characters outside it. Use UTF-8 there and never raise on an unprintable character."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def main(argv=None) -> int:
    _safe_console()
    ap = argparse.ArgumentParser(
        prog="x-secure",
        description="X-Secure — Antivirus / browser safety / security audit toolkit",
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="open the graphical app (default)")
    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("path")
    _add_scan_options(s)
    _add_scan_options(sub.add_parser("quickscan", help="scan high-risk locations (Startup, Temp, Downloads, AppData...)"))
    _add_scan_options(sub.add_parser("fullscan", help="scan every fixed drive, high-risk locations first"))
    sub.add_parser("audit", help="run the system security audit")
    u = sub.add_parser("url", help="check a URL")
    u.add_argument("url")
    m = sub.add_parser("monitor", help="real-time protection in the terminal")
    m.add_argument("paths", nargs="+")
    m.add_argument("--auto-quarantine", action="store_true")
    m.add_argument("--canaries", action="store_true")
    sub.add_parser("update", help="download threat feeds")
    al = sub.add_parser("allow", help="trust a file (or SHA-256) so it is no longer flagged")
    al.add_argument("target")
    sc = sub.add_parser("schedule", help="automatic scans with Windows Task Scheduler (no admin needed)")
    sc.add_argument("action", choices=["set", "show", "off", "run"],
                    help="set a schedule, show it, turn it off, or run it now")
    sc.add_argument("--at", default="13:00", help="24-hour time, e.g. 13:00 (default)")
    sc.add_argument("--weekly", metavar="DAY", help="weekly on DAY (MON..SUN) instead of daily")
    sc.add_argument("--full", action="store_true", help="full PC scan instead of a quick scan")
    nh = sub.add_parser("nativehost", help="browser-extension bridge (scan downloads with the desktop scanner)")
    nh.add_argument("action", choices=["install", "uninstall", "status", "serve"])
    nh.add_argument("--extension-id", action="append", default=[],
                    help="id shown on chrome://extensions or edge://extensions (repeat for both browsers)")
    nh.add_argument("browser_args", nargs="*", help=argparse.SUPPRESS)   # the browser passes its own arguments
    bm = sub.add_parser("benchmark", help="false-positive rate on clean files + detection of harmless samples")
    bm.add_argument("paths", nargs="*", help="clean folders to use (default: System32 and Program Files)")
    bm.add_argument("--limit", type=int, default=20000, help="max clean files to scan (default 20000)")
    a = ap.parse_args(argv)

    if a.cmd in (None, "gui"):
        from sentinel.gui import run
        run()
        return 0

    if a.cmd == "scan":
        import os
        from sentinel.engine import default_excludes
        if not os.path.exists(a.path):
            print(f"Path not found: {a.path}", file=sys.stderr)
            return 2
        return _run_scan([a.path], default_excludes(), a)

    if a.cmd in ("quickscan", "fullscan"):
        from sentinel.engine import full_scan_plan, quick_scan_plan
        roots, exclude = quick_scan_plan() if a.cmd == "quickscan" else full_scan_plan()
        return _run_scan(roots, exclude, a)

    if a.cmd == "audit":
        from sentinel.sysaudit import run_audit
        rep = run_audit()
        print(f"Security score: {rep.score}/100\n")
        for f in rep.findings:
            print(f"[{f.severity.upper():6}] {f.category}: {f.title}")
            if f.detail:
                print(f"         {f.detail}")
            if f.fix:
                print(f"         Fix: {f.fix}")
        return 0

    if a.cmd == "url":
        from sentinel.webguard import analyze_url
        v = analyze_url(a.url)
        print(f"{v.verdict.upper()} (risk {v.score}/100)")
        for r in v.reasons:
            print(f"  - {r}")
        return 1 if v.verdict != "clean" else 0

    if a.cmd == "monitor":
        from sentinel.monitor import ProcessWatcher, RealtimeMonitor
        from sentinel.scanner import Scanner
        emit = lambda al: print(al, f"| {al.detail}" if al.detail else "", flush=True)
        sc = Scanner()
        mon = RealtimeMonitor(sc, a.paths, emit, a.auto_quarantine, a.canaries)
        pw = ProcessWatcher(emit, scanner=sc)
        try:
            mon.start()
            pw.start()
        except RuntimeError as e:
            mon.stop()
            print(e, file=sys.stderr)
            return 2
        print("X-Secure protection running. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mon.stop()
            pw.stop()
        return 0

    if a.cmd == "allow":
        import re
        from pathlib import Path
        from sentinel.scanner import _hash_and_sample, add_to_allowlist
        if re.fullmatch(r"[0-9a-fA-F]{64}", a.target):
            sha = a.target.lower()
        else:
            try:
                sha = _hash_and_sample(Path(a.target))[0]
            except OSError as e:
                print(f"Cannot read {a.target}: {e}", file=sys.stderr)
                return 2
        add_to_allowlist(sha, "" if len(a.target) == 64 else a.target)
        print(f"Allowlisted {sha}")
        return 0

    if a.cmd == "schedule":
        from sentinel import schedule
        if a.action == "set":
            ok, msg = schedule.create(a.at, "fullscan" if a.full else "quickscan", a.weekly)
        elif a.action == "off":
            ok, msg = schedule.remove()
        elif a.action == "run":
            ok, msg = schedule.run_now()
            msg = "Scheduled scan started in the background." if ok else msg
        else:
            ok, msg = True, f"Scheduled scan: {schedule.describe()}"
            last = schedule.last_result()
            if last:
                msg += (f"\nLast scheduled run: {time.strftime('%Y-%m-%d %H:%M', time.localtime(last['time']))}, "
                        f"{last['files']:,} files, {last['threats']} flagged")
        print(msg)
        return 0 if ok else 1

    if a.cmd == "benchmark":
        from sentinel import benchmark
        res = benchmark.run(a.paths or None, a.limit,
                            lambda n: print(f"  ... {n:,} clean files scanned", file=sys.stderr, flush=True))
        print(benchmark.report(res))
        return 0

    if a.cmd == "nativehost":
        from sentinel import nativehost
        if a.action == "serve":
            return nativehost.serve()
        if a.action == "install":
            try:
                for browser, key in nativehost.install(a.extension_id):
                    print(f"Registered for {browser}: HKCU\\{key}")
            except ValueError as e:
                print(e, file=sys.stderr)
                return 2
            print("Restart the browser. Finished downloads are now scanned by X-Secure.")
            return 0
        if a.action == "uninstall":
            print("Removed from: " + (", ".join(nativehost.uninstall()) or "nothing was installed"))
            return 0
        for browser, path in nativehost.status().items():
            print(f"{browser}: {'installed -> ' + path if path else 'not installed'}")
        return 0

    if a.cmd == "update":
        from sentinel.updater import update_feeds
        for k, v in update_feeds().items():
            print(f"{k}: {v}")
        return 0
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()  # required for parallel scanning in a PyInstaller .exe
    sys.exit(main())
