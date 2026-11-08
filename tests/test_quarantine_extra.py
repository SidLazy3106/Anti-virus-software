"""Quarantine edge cases: DPAPI failures, damaged files and index, the cross-process lock and refused platforms."""
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sentinel import config, quarantine


class DpapiAndFileFormatTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_api_failures_become_oserrors_with_a_clear_message(self):
        failing = SimpleNamespace(
            crypt32=SimpleNamespace(CryptProtectData=lambda *a: 0, CryptUnprotectData=lambda *a: 0),
            kernel32=SimpleNamespace(LocalFree=lambda p: None))
        with mock.patch.object(quarantine.ctypes, "windll", failing, create=True):
            with self.assertRaisesRegex(OSError, "could not encrypt"):
                quarantine._dpapi(b"data", b"e", True)
            with self.assertRaisesRegex(OSError, "could not decrypt"):
                quarantine._dpapi(b"data", b"e", False)

    def test_round_trip_of_small_data(self):
        blob = quarantine._dpapi(b"secret", b"entropy", True)
        self.assertNotIn(b"secret", blob)
        self.assertEqual(quarantine._dpapi(blob, b"entropy", False), b"secret")
        with self.assertRaises(OSError):
            quarantine._dpapi(blob, b"other entropy", False)

    def test_decrypt_refuses_foreign_and_truncated_files(self):
        foreign = self.d / "foreign.qz"
        foreign.write_bytes(b"NOPE" + b"x" * 20)
        with self.assertRaisesRegex(ValueError, "not an encrypted quarantine file"):
            quarantine._decrypt_file(foreign, self.d / "out.bin", b"e")
        truncated = self.d / "trunc.qz"
        truncated.write_bytes(quarantine.MAGIC + struct.pack("<I", 500) + b"short")
        with self.assertRaisesRegex(ValueError, "truncated"):
            quarantine._decrypt_file(truncated, self.d / "out2.bin", b"e")
        self.assertFalse((self.d / "out2.bin").exists() or (self.d / "out2.bin.partial").exists())


class IndexTests(unittest.TestCase):
    def setUp(self):
        config.ensure_dirs()
        self.index = config.QUARANTINE_DIR / "index.json"
        self.backup = self.index.read_bytes() if self.index.exists() else None

        def restore():
            for f in config.QUARANTINE_DIR.glob("index.corrupt-*.json"):
                f.unlink()
            if self.backup is None:
                self.index.unlink(missing_ok=True)
            else:
                self.index.write_bytes(self.backup)
        self.addCleanup(restore)

    def test_missing_unreadable_and_damaged_index(self):
        self.index.unlink(missing_ok=True)
        self.assertEqual(quarantine._load(), {})
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            self.assertEqual(quarantine._load(), {})
        self.index.write_text("{ this is not json")
        self.assertEqual(quarantine._load(), {})
        kept = list(config.QUARANTINE_DIR.glob("index.corrupt-*.json"))
        self.assertEqual(len(kept), 1)                                   # set aside, not silently overwritten
        self.assertEqual(kept[0].read_text(), "{ this is not json")

    def test_damaged_index_that_cannot_be_moved_still_returns_empty(self):
        self.index.write_text("nonsense")
        with mock.patch.object(quarantine.os, "replace", side_effect=OSError("locked")):
            self.assertEqual(quarantine._load(), {})


class LockTests(unittest.TestCase):
    def test_lock_is_taken_released_and_reusable(self):
        for _ in range(2):                                             # first run creates the lock file, second reuses it
            with quarantine._locked():
                pass
        self.assertGreater((config.QUARANTINE_DIR / "index.lock").stat().st_size, 0)

    def test_waits_for_a_busy_lock_then_succeeds(self):
        attempts = [OSError("busy"), OSError("busy"), None]
        with mock.patch.object(quarantine, "_lock_file", side_effect=attempts), \
                mock.patch.object(quarantine, "_unlock_file") as unlock, \
                mock.patch.object(quarantine.time, "sleep") as sleep:
            with quarantine._locked():
                pass
        self.assertEqual(sleep.call_count, 2)
        unlock.assert_called_once()

    def test_gives_up_with_a_clear_error_when_the_lock_never_frees(self):
        with mock.patch.object(quarantine, "_lock_file", side_effect=OSError("busy")), \
                mock.patch.object(quarantine.time, "sleep"):
            with self.assertRaisesRegex(quarantine.QuarantineError, "busy"):
                with quarantine._locked(timeout=0):
                    self.fail("must not run without the lock")


class PublicApiTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.f = self.d / "evil.bin"
        self.f.write_bytes(b"payload" * 100)

    def test_refused_without_dpapi_and_the_file_is_untouched(self):
        with mock.patch.object(quarantine, "IS_WIN", False):
            self.assertFalse(quarantine.available())
            with self.assertRaisesRegex(quarantine.QuarantineError, "left untouched"):
                quarantine.quarantine_file(self.f)
        self.assertTrue(self.f.exists())

    def test_quarantine_error_is_an_oserror(self):
        self.assertTrue(issubclass(quarantine.QuarantineError, OSError))
        self.assertTrue(issubclass(quarantine.ItemNotFoundError, quarantine.QuarantineError))

    def test_failed_encryption_or_removal_leaves_no_blob_and_keeps_the_original(self):
        before = set(config.QUARANTINE_DIR.glob("*.qz"))
        with mock.patch.object(quarantine, "_encrypt_file", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                quarantine.quarantine_file(self.f)
        with mock.patch.object(quarantine.os, "remove", side_effect=PermissionError("in use")):
            with self.assertRaises(PermissionError):
                quarantine.quarantine_file(self.f)
        self.assertTrue(self.f.exists())
        self.assertEqual(set(config.QUARANTINE_DIR.glob("*.qz")), before)       # the half-made blobs were removed

    def test_unknown_id_is_reported_clearly(self):
        with self.assertRaises(quarantine.ItemNotFoundError):
            quarantine.restore("does-not-exist")

    def test_restore_never_overwrites_and_can_go_elsewhere(self):
        data = self.f.read_bytes()
        qid = quarantine.quarantine_file(self.f, "why", "sha")
        self.f.write_bytes(b"a new file with the same name")                   # the original name is taken again
        restored = quarantine.restore(qid)
        self.assertEqual(restored.name, "evil.bin.restored")
        self.assertEqual(restored.read_bytes(), data)
        qid = quarantine.quarantine_file(restored)
        elsewhere = self.d / "new" / "dir" / "back.bin"
        self.assertEqual(quarantine.restore(qid, dest=elsewhere), elsewhere)
        self.assertEqual(elsewhere.read_bytes(), data)

    def test_delete_removes_the_item_and_is_quiet_for_unknown_ids(self):
        qid = quarantine.quarantine_file(self.f)
        self.assertTrue((config.QUARANTINE_DIR / f"{qid}.qz").exists())
        quarantine.delete(qid)
        self.assertFalse((config.QUARANTINE_DIR / f"{qid}.qz").exists())
        self.assertNotIn(qid, [i["id"] for i in quarantine.list_items()])
        quarantine.delete("never-existed")

    def test_index_survives_two_items(self):
        a = quarantine.quarantine_file(self.f)
        g = self.d / "second.bin"
        g.write_bytes(b"x")
        b = quarantine.quarantine_file(g)
        ids = [i["id"] for i in quarantine.list_items()]
        self.assertTrue({a, b} <= set(ids))
        self.assertEqual(json.loads((config.QUARANTINE_DIR / "index.json").read_text())[a]["format"], quarantine.FORMAT)
        quarantine.delete(a)
        quarantine.delete(b)
        self.assertEqual(os.path.exists(self.f), False)


if __name__ == "__main__":
    unittest.main()
