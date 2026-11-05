"""Host-only real-git checkout identity regressions; not a producer proof."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).with_name("verify-cross-backend-static-facts-v0.py")
SPEC = importlib.util.spec_from_file_location("static_facts_checkout_wave35", MODULE)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class GitCheckoutAdmission(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Host Fixture")
        self.git("config", "user.email", "host@example.invalid")
        self.source = self.repo / "tracked.ores"
        self.source.write_text("pub fnc main(): int { return 42; }\n")
        self.git("add", "tracked.ores")
        self.git("commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True,
            check=True,
        )

    def test_immutable_head_with_clean_worktree_is_admitted_as_identity_only(self):
        self.assertEqual(gate.head(self.repo, self.sha), self.sha)

    def test_expected_sha_mismatch_fails_even_when_worktree_is_clean(self):
        with self.assertRaisesRegex(RuntimeError, "wrong reviewed commit"):
            gate.head(self.repo, "0" * 40)

    def test_tracked_mutation_fails_closed(self):
        self.source.write_text("pub fnc main(): int { return 43; }\n")
        with self.assertRaisesRegex(RuntimeError, "checkout contains staged"):
            gate.head(self.repo, self.sha)

    def test_untracked_source_fails_closed(self):
        (self.repo / "untracked.ores").write_text("pub fnc hidden() {}\n")
        with self.assertRaisesRegex(RuntimeError, "checkout contains staged"):
            gate.head(self.repo, self.sha)

    def test_staged_new_source_fails_closed(self):
        (self.repo / "staged.ores").write_text("pub fnc hidden() {}\n")
        self.git("add", "staged.ores")
        with self.assertRaisesRegex(RuntimeError, "checkout contains staged"):
            gate.head(self.repo, self.sha)


if __name__ == "__main__":
    unittest.main()
