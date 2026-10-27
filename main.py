"""X-Secure entry point.  python main.py [gui|scan|audit|url|monitor|update]"""
import argparse
import sys
import time


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="x-secure",
        description="X-Secure — Antivirus / browser safety / security audit toolkit",
    )
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="open the graphical app (default)")
    s = sub.add_parser("scan", help="scan a file or folder")
    s.add_argument("path")
    s.add_argument("--quarantine", action="store_true", help="quarantine malicious files")
    sub.add_parser("audit", help="run the system security audit")
    u = sub.add_parser("url", help="check a URL")
    u.add_argument("url")
    m = sub.add_parser("monitor", help="real-time protection in the terminal")
    m.add_argument("paths", nargs="+")
    m.add_argument("--auto-quarantine", action="store_true")
    m.add_argument("--canaries", action="store_true")
    sub.add_parser("update", help="download threat feeds")
    a = ap.parse_args(argv)

    if a.cmd in (None, "gui"):
        from sentinel.gui import run
        run()
        return 0

    if a.cmd == "scan":
        from sentinel import quarantine
        from sentinel.scanner import CLEAN, MALICIOUS, Scanner
        sc, n, hits = Scanner(), 0, 0
        for r in sc.scan_tree(a.path):
            n += 1
            if r.verdict != CLEAN:
                hits += 1
                print(f"{r.verdict.upper():10} {r.score:3}  {r.path}")
                for why in r.reasons:
                    print(f"             - {why}")
                if a.quarantine and r.verdict == MALICIOUS:
                    quarantine.quarantine_file(r.path, "; ".join(r.reasons), r.sha256)
                    print("             > quarantined")
        print(f"\n{n} files scanned, {hits} flagged")
        return 1 if hits else 0

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
        mon = RealtimeMonitor(Scanner(), a.paths, emit, a.auto_quarantine, a.canaries)
        pw = ProcessWatcher(emit)
        mon.start()
        pw.start()
        print("X-Secure protection running. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mon.stop()
            pw.stop()
        return 0

    if a.cmd == "update":
        from sentinel.updater import update_feeds
        for k, v in update_feeds().items():
            print(f"{k}: {v}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
