"""Tests for Quarantine."""
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from sentinel import config, quarantine


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_round_trip_is_encrypted_with_no_key_stored(self):
        f = self.d / "evil.bin"
        data = os.urandom(9 * (1 << 20) + 123)  # spans several encryption chunks
        f.write_bytes(data)
        qid = quarantine.quarantine_file(f, "test", "abc")
        self.assertFalse(f.exists())
        stored = (config.QUARANTINE_DIR / f"{qid}.qz").read_bytes()
        self.assertNotIn(data[1000:1064], stored)
        item = quarantine.list_items()[0]
        if quarantine.available():
            self.assertEqual(item["format"], quarantine.FORMAT)
            self.assertNotIn("key", item)                       # nothing in the folder can decrypt it
        out = quarantine.restore(qid)
        self.assertEqual(out.read_bytes(), data)
        self.assertEqual(quarantine.list_items(), [])

    @unittest.skipUnless(quarantine.available(), "DPAPI is Windows-only")
    def test_tampered_or_swapped_files_are_never_restored(self):
        a, b = self.d / "a.bin", self.d / "b.bin"
        a.write_bytes(b"A" * 5000)
        b.write_bytes(b"B" * 5000)
        qa, qb = quarantine.quarantine_file(a), quarantine.quarantine_file(b)
        qa_path, qb_path = config.QUARANTINE_DIR / f"{qa}.qz", config.QUARANTINE_DIR / f"{qb}.qz"
        raw = bytearray(qa_path.read_bytes())
        raw[200] ^= 0xFF
        qa_path.write_bytes(bytes(raw))
        with self.assertRaises(OSError):
            quarantine.restore(qa)
        self.assertFalse(a.exists() or Path(str(a) + ".partial").exists())   # nothing half-written appears
        good_b = qb_path.read_bytes()
        qa_path.write_bytes(good_b)                              # swap: b's blob under a's id
        with self.assertRaises(OSError):
            quarantine.restore(qa)
        self.assertEqual(quarantine.restore(qb).read_bytes(), b"B" * 5000)
        quarantine.delete(qa)

    def test_old_xor_items_still_restore(self):
        f = self.d / "old.bin"
        data = os.urandom(5000)
        key = os.urandom(quarantine.KEY_LEN)
        qid = "legacy0000000000000000000000000001"
        config.ensure_dirs()
        f.write_bytes(data)
        quarantine._xor_stream(f, config.QUARANTINE_DIR / f"{qid}.qz", key)
        f.unlink()
        idx = quarantine._load()
        idx[qid] = {"original_path": str(f), "sha256": "", "reason": "", "time": time.time(), "size": 5000,
                    "key": key.hex()}
        quarantine._save(idx)
        self.assertEqual(quarantine.restore(qid).read_bytes(), data)
