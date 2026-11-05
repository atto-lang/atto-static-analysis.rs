"""Pure host identity gate tests; no producer/compiler/analyzer executes."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parent / "verify-cross-backend-static-facts-v0.py"
SPEC = importlib.util.spec_from_file_location("static_facts_wave32", SOURCE)
facts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(facts)


class SchemaValidatedFixture:
    """Only for the post-schema identity/semantic policy tests below."""
    def validate(self, document):
        pass


class StaticFactsAdmissionFences(unittest.TestCase):
    def setUp(self):
        self.source = facts.PURE
        self.base = {
            "version": facts.VERSION,
            "unit": "sha256:" + hashlib.sha256(self.source).hexdigest(),
            "procedures": [{"id": "__root__.main/0", "loops": []}],
            "edges": [], "taint_sources": [], "flows": [],
            "sinks": [], "permission_checks": [], "callback_orderings": [],
        }
        self.validator = SchemaValidatedFixture()

    def admit(self, doc):
        return facts.validate_fact(doc, self.source, {}, self.validator)

    def test_exact_source_and_expected_minimal_pure_procedure(self):
        self.assertEqual(self.admit(self.base), self.base)

    def test_valid_shape_with_forged_source_digest_must_still_be_denied(self):
        changed = dict(self.base, unit="sha256:" + "0" * 64)
        with self.assertRaisesRegex(RuntimeError, "source identity"):
            self.admit(changed)

    def test_unsupported_version_and_extra_procedure_are_denied(self):
        with self.assertRaisesRegex(RuntimeError, "fact version"):
            self.admit(dict(self.base, version="ores-static-facts/v1"))
        extra = dict(self.base, procedures=[
            {"id": "__root__.main/0", "loops": []},
            {"id": "__root__.unexpected/0", "loops": []},
        ])
        with self.assertRaisesRegex(RuntimeError, "additional functions or loops"):
            self.admit(extra)

    def test_each_nonempty_effect_or_proof_array_is_denied(self):
        keys = ("edges", "taint_sources", "flows", "sinks",
                "permission_checks", "callback_orderings")
        for key in keys:
            with self.subTest(key=key), self.assertRaisesRegex(
                    RuntimeError, "unsupported effect/proof"):
                self.admit(dict(self.base, **{key: [{"untrusted": True}]}))

    def test_backend_selection_remains_explicit_not_a_proof(self):
        class Args:
            producer_repo = Path("/tmp/producer")
            backend_compiler = "/tmp/unexecuted-compiler"
            backend_compiler_sha256 = "a" * 64
        for backend, expected in (
                ("js", "node"), ("rs", "cargo"), ("net", "dotnet"),
                ("forge", "python3"), ("llvm", "python3"),
                ("wasm", "node")):
            with self.subTest(backend=backend):
                args = Args()
                args.backend = backend
                command = facts.producer_command(args, Path("/tmp/source.ores"))
                self.assertEqual(command[0], expected)
        args.backend = "unsupported"
        with self.assertRaisesRegex(RuntimeError, "unsupported backend"):
            facts.producer_command(args, Path("/tmp/source.ores"))


if __name__ == "__main__":
    unittest.main()
