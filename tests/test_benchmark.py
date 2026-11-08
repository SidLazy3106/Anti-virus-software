"""The benchmark: its corpus choice, the harmless detection samples, the false-positive run and the report text."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel import benchmark
from sentinel.verdict import Verdict


class CorpusTests(unittest.TestCase):
    def test_default_corpus_uses_existing_system_folders_only(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "System32").mkdir()
        (root / "pf").mkdir()
        env = {"SystemRoot": str(root), "ProgramFiles": str(root / "pf"), "ProgramFiles(x86)": str(root / "missing")}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(benchmark.default_corpus(), [root / "System32", root / "pf"])
        with mock.patch.dict(os.environ, {"SystemRoot": str(root / "nope"), "ProgramFiles": "", "ProgramFiles(x86)": ""}):
            self.assertEqual(benchmark.default_corpus(), [])


class SyntheticSampleTests(unittest.TestCase):
    def test_every_sample_is_detected_by_the_scanner(self):
        from sentinel.scanner import Scanner
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        samples = benchmark._synthetic(d)
        self.assertGreaterEqual(len(samples), 9)
        sc = Scanner(log=False)
        missed = [label for label, p in samples if sc.scan_file(p).verdict == Verdict.CLEAN]
        self.assertEqual(missed, [])

    def test_alternate_stream_sample_is_only_made_on_windows(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(benchmark.os, "name", "posix"):
            labels = [label for label, _ in benchmark._synthetic(d)]
        self.assertNotIn("program hidden in an alternate data stream", labels)


class RunAndReportTests(unittest.TestCase):
    def test_false_positive_run_progress_limit_and_report(self):
        corpus = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, corpus, True)
        for i in range(1010):
            (corpus / f"clean{i}.txt").write_text(str(i))
        (corpus / "odd.ps1").write_text("vssadmin delete shadows /all\nSet-MpPreference -DisableRealtimeMonitoring $true\n")
        seen = []
        res = benchmark.run([corpus], limit=1011, progress=seen.append, workers=1)
        self.assertEqual(seen[0], 1000)
        self.assertEqual((res["files"], len(res["flagged"])), (1011, 1))
        self.assertEqual(res["samples"], len(res["detection"]))
        self.assertEqual(res["detected"], res["samples"])
        text = benchmark.report(res)
        for expected in ("Clean corpus", "false-positive rate", "Synthetic detection samples", "OK  "):
            self.assertIn(expected, text)

    def test_report_lists_flagged_files_and_reasons(self):
        res = {"corpus": ["C:/x"], "files": 10, "seconds": 1.0, "errors": 0, "fp_rate": 0.1,
               "flagged": [("C:/x/bad.exe", Verdict.SUSPICIOUS, 40, ["why"])],
               "top_reasons": [("Executable disguised as a .pdf file", 1)],
               "detection": [("sample", Verdict.CLEAN, 0)], "detected": 0, "samples": 1}
        text = benchmark.report(res)
        self.assertIn("C:/x/bad.exe", text)
        self.assertIn("MISS", text)
        self.assertIn("Executable disguised", text)

    def test_default_corpus_is_used_when_none_is_given(self):
        with mock.patch.object(benchmark, "default_corpus", return_value=[]):
            res = benchmark.run(None, limit=10)
        self.assertEqual(res["files"], 0)


if __name__ == "__main__":
    unittest.main()
