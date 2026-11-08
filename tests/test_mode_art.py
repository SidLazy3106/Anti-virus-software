"""Tests for ModeArt."""
import unittest


class ModeArtTests(unittest.TestCase):
    """The mode-card animations are illustrations only: fixed curves, labelled as such, never live measurements."""

    def test_curves_are_deterministic_bounded_and_match_the_legend(self):
        from sentinel import mode_art, optimizer
        for key in optimizer.PROFILES:
            for i in range(0, 11):
                x = i / 10
                ys = mode_art.curves(key, x)
                self.assertEqual(ys, mode_art.curves(key, x))
                self.assertEqual(len(ys), len(mode_art.LEGEND[key]))
                self.assertTrue(all(0 <= y <= 1 for y in ys), (key, x, ys))

    def test_every_mode_is_labelled_as_an_illustration(self):
        from sentinel import mode_art, optimizer
        self.assertEqual(mode_art.CONCEPT_MS, 1200)
        for key in optimizer.PROFILES:
            self.assertTrue(mode_art.DISCLAIMERS[key].startswith("Illustration of intended behavior"))
            self.assertIn("not", mode_art.DISCLAIMERS[key])
            self.assertTrue(mode_art.TITLES[key] and mode_art.CAPTIONS[key])
        self.assertLess(mode_art.curves("eco", 1.0)[0], mode_art.curves("eco", 0.0)[0])   # eco: demand falls

    def test_art_module_reads_no_system_data(self):
        import inspect
        from sentinel import mode_art
        src = inspect.getsource(mode_art)
        for banned in ("psutil", "subprocess", "cpu_percent", "virtual_memory"):
            self.assertNotIn(banned, src)
