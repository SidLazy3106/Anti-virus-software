"""Tests for NativeHost."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


class NativeHostTests(unittest.TestCase):
    """The browser bridge, tested with the real host process. Registry work uses a scratch HKCU key only."""
    REG = r"Software\XSecureTest\NativeHosts"
    ROOT = Path(__file__).resolve().parent.parent

    def setUp(self):
        from sentinel import nativehost
        self.nh = nativehost
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.bad = self.d / "invoice.pdf.exe"
        self.bad.write_bytes(b"MZ" + b"\0" * 200)

    def tearDown(self):
        import winreg
        for sub in ("chrome", "edge", ""):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.REG + "\\" + self.nh.HOST_NAME)
            except OSError:
                pass
        for k in (self.REG, r"Software\XSecureTest"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, k)
            except OSError:
                pass

    @staticmethod
    def frame(obj):
        import json as _j
        import struct as _s
        b = _j.dumps(obj).encode()
        return _s.pack("<I", len(b)) + b

    @staticmethod
    def unframe(data):
        import json as _j
        import struct as _s
        out = []
        while len(data) >= 4:
            (n,) = _s.unpack("<I", data[:4])
            out.append(_j.loads(data[4:4 + n]))
            data = data[4 + n:]
        return out

    def test_protocol_and_validation(self):
        import io
        reqs = [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}, {"type": "scan", "path": "relative.exe"},
                {"type": "scan", "path": str(self.d)}, {"type": "scan", "path": str(self.d / "missing.exe")},
                {"type": "launch", "path": str(self.bad)}]
        out = io.BytesIO()
        self.assertEqual(self.nh.serve(io.BytesIO(b"".join(self.frame(r) for r in reqs)), out), 0)
        ping, scan, rel, folder, missing, launch = self.unframe(out.getvalue())
        self.assertTrue(ping["ok"])
        self.assertTrue(scan["ok"])
        self.assertNotEqual(scan["verdict"], "clean")
        self.assertEqual(scan["name"], "invoice.pdf.exe")
        for bad in (rel, folder, missing, launch):
            self.assertFalse(bad["ok"])
        self.assertTrue(self.bad.exists())                       # the host never moves or deletes anything

    def test_oversized_message_is_refused(self):
        import io
        import struct as _s
        out = io.BytesIO()
        self.assertEqual(self.nh.serve(io.BytesIO(_s.pack("<I", 50 << 20)), out), 1)
        self.assertFalse(self.unframe(out.getvalue())[0]["ok"])

    def _talk(self, cmd, reqs):
        import subprocess
        p = subprocess.run(cmd, input=b"".join(self.frame(r) for r in reqs), capture_output=True, timeout=120,
                           env={**os.environ, "XSECURE_HOME": str(self.d / "home")})
        return self.unframe(p.stdout), p

    def test_real_host_process(self):
        replies, p = self._talk([sys.executable, str(self.ROOT / "main.py"), "nativehost", "serve",
                                 "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"],
                                [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}])
        self.assertEqual(len(replies), 2, p.stderr)
        self.assertTrue(replies[0]["ok"])
        self.assertIn(replies[1]["verdict"], ("suspicious", "malicious"))

    def test_install_launcher_and_uninstall(self):
        os.environ["XSECURE_HOME"], old = str(self.d / "home"), os.environ.get("XSECURE_HOME")
        try:
            with self.assertRaises(ValueError):
                self.nh.install(["not-an-id"], browsers=("chrome",), reg_base=self.REG)
            ext_id = "abcdefghijklmnopabcdefghijklmnop"
            done = self.nh.install([ext_id], browsers=("chrome",), reg_base=self.REG)
            self.assertEqual(len(done), 1)
            man_path = self.nh.status(("chrome",), reg_base=self.REG)["chrome"]
            man = __import__("json").loads(Path(man_path).read_text(encoding="utf-8"))
            self.assertEqual(man["name"], self.nh.HOST_NAME)
            self.assertEqual(man["allowed_origins"], [f"chrome-extension://{ext_id}/"])
            launcher = Path(man["path"])
            self.assertTrue(launcher.is_file())
            replies, p = self._talk(["cmd", "/c", str(launcher), f"chrome-extension://{ext_id}/"],
                                    [{"type": "ping"}, {"type": "scan", "path": str(self.bad)}])
            self.assertEqual(len(replies), 2, p.stderr)               # the exact program the browser starts
            self.assertNotEqual(replies[1]["verdict"], "clean")
            self.assertEqual(self.nh.uninstall(("chrome",), reg_base=self.REG), ["chrome"])
            self.assertIsNone(self.nh.status(("chrome",), reg_base=self.REG)["chrome"])
            self.assertFalse(launcher.exists())
        finally:
            if old is None:
                os.environ.pop("XSECURE_HOME", None)
            else:
                os.environ["XSECURE_HOME"] = old

    def test_extension_sends_finished_downloads_to_the_host(self):
        """Runs the extension's real background.js in Node with a mocked browser API whose sendNativeMessage
        starts the real host process."""
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js not installed")
        ext = self.ROOT / "browser_extension"
        harness = self.d / "harness.js"
        harness.write_text("""
const fs = require("fs"), path = require("path"), cp = require("child_process"), vm = require("vm");
const EXT = process.argv[2], PY = process.argv[3], MAIN = process.argv[4], FILE = process.argv[5];
const listeners = {}, notes = [];
const ev = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
function frame(o) { const b = Buffer.from(JSON.stringify(o)); const h = Buffer.alloc(4); h.writeUInt32LE(b.length); return Buffer.concat([h, b]); }
const chrome = {
  runtime: { getURL: (p) => "file://" + path.join(EXT, p), onMessage: ev("msg"), lastError: null,
    sendNativeMessage: (host, msg, cb) => {
      const out = cp.execFileSync(PY, [MAIN, "nativehost", "serve"], { input: frame(msg) });
      const n = out.readUInt32LE(0); cb(JSON.parse(out.slice(4, 4 + n).toString()));
    } },
  webNavigation: { onBeforeNavigate: ev("nav") }, storage: { session: { get: async () => ({}) } },
  downloads: { onCreated: ev("created"), onChanged: ev("changed"),
               search: async ({ id }) => [{ id, filename: FILE }] },
  notifications: { create: (id, opt) => notes.push(opt) }, tabs: { update() {} }, action: {},
};
const ctx = { chrome, console, URL, fetch: async () => ({ json: async () => ({ domains: [] }) }) };
ctx.importScripts = (f) => vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx);
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx);
(async () => {
  await listeners.changed({ id: 7, state: { current: "in_progress" } });
  const before = notes.length;
  await listeners.changed({ id: 7, state: { current: "complete" } });
  console.log(JSON.stringify({ before, notes }));
})();
""", encoding="utf-8")
        import json as _j
        import subprocess
        p = subprocess.run([node, str(harness), str(ext), sys.executable, str(self.ROOT / "main.py"), str(self.bad)],
                           capture_output=True, text=True, timeout=120,
                           env={**os.environ, "XSECURE_HOME": str(self.d / "home")})
        self.assertEqual(p.returncode, 0, p.stderr)
        res = _j.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(res["before"], 0)                       # nothing until the download completes
        self.assertEqual(len(res["notes"]), 1)
        self.assertIn("X-Secure:", res["notes"][0]["title"])
        self.assertIn("invoice.pdf.exe", res["notes"][0]["message"])
