"""leakguard entropy-detection tests (stdlib unittest)."""
import unittest

from leakguard.engine import load_rules, scan_text
from leakguard.entropy import (EntropyOptions, entropy_findings, shannon_entropy)

# A 38-char token with many distinct characters -> high entropy, no pattern match.
HIGH = "Zk8Qv3Lm9Xr2Tp7Wn5Bc1Yd6Hg4As0UeIoPq"
GIT_SHA = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40-hex, benign


class TestEntropy(unittest.TestCase):
    def setUp(self):
        self.opts = EntropyOptions(enabled=True)

    def test_entropy_value(self):
        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy(HIGH), 4.0)

    def test_flags_high_entropy_token(self):
        f = entropy_findings("value: " + HIGH, set(), "f.txt", self.opts, [])
        self.assertTrue(any(x.match == HIGH for x in f))

    def test_low_entropy_prose_not_flagged(self):
        f = entropy_findings("the quick brown fox jumps over the lazy dog again",
                             set(), "f.txt", self.opts, [])
        self.assertEqual(f, [])

    def test_disabled_is_noop(self):
        off = EntropyOptions(enabled=False)
        self.assertEqual(entropy_findings("x " + HIGH, set(), "f.txt", off, []), [])

    def test_lockfile_skipped(self):
        f = entropy_findings("x " + HIGH, set(), "yarn.lock", self.opts, [])
        self.assertEqual(f, [])

    def test_allow_list_honored(self):
        f = entropy_findings("x " + HIGH, {HIGH}, "f.txt", self.opts, [])
        self.assertEqual(f, [])

    def test_git_sha_not_flagged(self):
        f = entropy_findings("commit " + GIT_SHA, set(), "CHANGELOG.md", self.opts, [])
        self.assertFalse(any(x.match == GIT_SHA for x in f))

    def test_threshold_tunable(self):
        strict = EntropyOptions(enabled=True, b64_threshold=6.0)
        self.assertEqual(entropy_findings("v " + HIGH, set(), "f.txt", strict, []), [])

    def test_overlap_with_pattern_match_skipped(self):
        rules, allow = load_rules()
        text = "key AKIA1234567890ABCDEF"
        rf = scan_text(text, rules, allow, path="f.txt")
        ef = entropy_findings(text, allow, "f.txt", self.opts, rf)
        self.assertFalse(any("AKIA" in x.match for x in ef))


if __name__ == "__main__":
    unittest.main()
