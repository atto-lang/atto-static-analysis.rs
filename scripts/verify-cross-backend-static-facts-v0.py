#!/usr/bin/env python3
"""Exact-head, source-backed .ores -> producer v0 JSON -> Rust advisory analyzer.

Uses only locally authorized checkouts and already-installed toolchains. Never
clones private repositories, mirrors Git trees, or injects GitHub credentials.
Requires jsonschema (Draft 2020-12); absence is a test infrastructure failure.
"""
import argparse
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

PURE = b"pub fnc main(): int { return 42; }\n"
NEGATIVE = b"pub fnc main(): int { return missing(1); }\n"
VERSION = "ores-static-facts/v0"


def fail(message):
    raise RuntimeError(message)


def command(argv, cwd, expected=(0,)):
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=180,
                                check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        fail("execution unavailable: " + str(error))
    if result.returncode not in expected:
        fail("unexpected exit {} for {}: {}".format(
            result.returncode, argv[0],
            result.stderr.decode("utf-8", errors="replace")[-1200:]))
    return result


def head(repo, expected):
    actual = command(["git", "rev-parse", "--verify", "HEAD"], repo).stdout.decode().strip()
    if actual != expected:
        fail("wrong reviewed commit in {}: expected {}, found {}".format(repo, expected, actual))
    # Deny edited tracked files. Ignored compiler artifacts may exist.
    status = command(["git", "diff", "--exit-code", "HEAD", "--"], repo)
    if status.returncode != 0:
        fail("tracked source was modified after reviewing SHA")
    return actual


def validate_fact(document, source, schema, validator):
    validator.validate(document)
    if document["version"] != VERSION:
        fail("unexpected fact version")
    identity = "sha256:" + hashlib.sha256(source).hexdigest()
    if document["unit"] != identity:
        fail("fact source identity does not match exact source bytes")
    expected = [{"id": "__root__.main/0", "loops": []}]
    if document["procedures"] != expected:
        fail("pure literal-main emitted additional functions or loops")
    for key in ("edges", "taint_sources", "flows", "sinks", "permission_checks",
                "callback_orderings"):
        if document.get(key, []) != []:
            fail("unsupported effect/proof facts were emitted: " + key)
    return document


def producer_command(args, path):
    root = args.producer_repo
    src = str(path)
    if args.backend == "js":
        return ["node", "bin/oreslang-jsc.mjs", "--static-facts", src]
    if args.backend == "rs":
        return ["cargo", "run", "--locked", "-q", "--bin", "oresc",
                "--", "--static-facts", src]
    if args.backend == "net":
        return ["dotnet", "run", "--project",
                "compiler/Ores.Net.Compiler/Ores.Net.Compiler.csproj",
                "-c", "Release", "--", "static-facts", src]
    if args.backend in ("forge", "llvm"):
        path_in_repo = ("verification/static_facts_v0.py"
                        if args.backend == "forge" else "tests/static_facts_v0.py")
        backend_bin = args.backend_compiler or str(root / "build" /
                        ("oresforge" if args.backend == "forge" else "oreslang-llvmc"))
        return ["python3", path_in_repo, "--compiler", str(pathlib.Path(backend_bin).resolve()),
                "--source", src]
    if args.backend == "wasm":
        if not args.backend_compiler:
            fail("Wasm requires --backend-compiler pointing to approved native LLVM compiler")
        return ["node", "scripts/static-facts-v0.mjs",
                "--compiler=" + str(pathlib.Path(args.backend_compiler).resolve()),
                "--source=" + src]
    fail("unsupported backend")


def analyzer(args, facts_file, mode, expected=(0,)):
    return command(["cargo", "run", "--locked", "-q", "-p", "ores-analyze", "--",
                    "--static-facts", str(facts_file), mode],
                   args.analyzer_repo, expected=expected)


def read_response(result):
    try:
        return json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        fail("expected one machine-readable JSON result: " + str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=["net", "rs", "js", "forge", "llvm", "wasm"],
                        required=True)
    parser.add_argument("--producer-repo", type=pathlib.Path, required=True)
    parser.add_argument("--analyzer-repo", type=pathlib.Path, required=True)
    parser.add_argument("--contract-repo", type=pathlib.Path, required=True)
    parser.add_argument("--producer-head", required=True)
    parser.add_argument("--analyzer-head", required=True)
    parser.add_argument("--contract-head", required=True)
    parser.add_argument("--backend-compiler", help="Authorized local executable for Forge/LLVM/Wasm")
    args = parser.parse_args()
    args.producer_repo = args.producer_repo.resolve(strict=True)
    args.analyzer_repo = args.analyzer_repo.resolve(strict=True)
    args.contract_repo = args.contract_repo.resolve(strict=True)

    try:
        from jsonschema import Draft202012Validator, ValidationError
    except ImportError:
        fail("Install jsonschema in this authorized test environment first")

    for root, sha in ((args.producer_repo, args.producer_head),
                      (args.analyzer_repo, args.analyzer_head),
                      (args.contract_repo, args.contract_head)):
        head(root, sha)

    schema_path = args.contract_repo / "contracts/analysis/static-facts.v0.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    with tempfile.TemporaryDirectory(prefix="ores-v0-e2e-") as temp:
        scratch = pathlib.Path(temp)
        source = scratch / "literal.ores"
        source.write_bytes(PURE)
        json_file = scratch / "facts.v0.json"

        facts = read_response(command(producer_command(args, source), args.producer_repo))
        validate_fact(facts, PURE, schema, validator)
        json_file.write_text(json.dumps(facts, separators=(",", ":")), encoding="utf-8")

        report = read_response(analyzer(args, json_file, "general"))
        if report.get("input_version") != VERSION or report.get("unit") != facts["unit"]:
            fail("Rust importer lost version/source identity")
        if report.get("producer_authenticated") is not False or not report.get("advisory_only"):
            fail("source hash was incorrectly promoted to producer attestation")
        if report.get("work_allocation_copy_bounds") != "unverified":
            fail("unknown resource bounds became a fabricated proof")
        for summary in report.get("report", {}).get("functions", {}).values():
            if any(summary.get(field) is not None for field in
                   ("allocations_upper_bound", "operations_upper_bound")):
                fail("numeric resource bounds unexpectedly became certified")

        for strict in ("soft", "hard"):
            analyzer(args, json_file, strict, expected=(2,))

        # Real parser/semantic negative: source is syntactically plausible but
        # contains an unresolved direct call; no exporter should emit JSON.
        source.write_bytes(NEGATIVE)
        bad_source = command(producer_command(args, source), args.producer_repo,
                             expected=tuple(range(1, 256)))
        if bad_source.stdout.strip().startswith(b"{"):
            fail("rejected source unexpectedly emitted machine-readable facts")

        # Tampered inputs must not become Rust-recognized proofs.
        def reject_modified(modified):
            json_file.write_text(json.dumps(modified), encoding="utf-8")
            analyzer(args, json_file, "general", expected=(2,))

        malformed = copy.deepcopy(facts)
        malformed["unit"] = "sha256:not-hex"
        try:
            validator.validate(malformed)
        except ValidationError:
            pass
        else:
            fail("canonical JSON Schema unexpectedly admitted malformed digest")
        reject_modified(malformed)

        forged = copy.deepcopy(facts)
        forged["edges"] = [{"from":"__root__.main/0", "to":"__root__.main/0",
                            "kind":"call", "fanout":1, "guard":"proved_bounded"}]
        validator.validate(forged)
        reject_modified(forged)

        looped = copy.deepcopy(facts)
        looped["procedures"][0]["loops"] = [
            {"id":"L1", "exit":"unknown", "safepoint":False}]
        validator.validate(looped)
        json_file.write_text(json.dumps(looped), encoding="utf-8")
        loop_result = read_response(analyzer(args, json_file, "general", expected=(1,)))
        codes = [entry.get("code") for entry in
                 loop_result.get("report", {}).get("diagnostics", [])]
        if "ORES-SA104" not in codes:
            fail("unproved while-loop fact did not produce ORES-SA104")

        loop_call = copy.deepcopy(looped)
        loop_call["edges"] = [{"from":"__root__.main/0", "to":"__root__.main/0",
                               "kind":"call", "fanout":1, "guard":"unproved",
                               "enclosing_loop":"L1"}]
        validator.validate(loop_call)
        reject_modified(loop_call)

        mismatch = copy.deepcopy(facts)
        mismatch["unit"] = "sha256:" + "0"*64
        validator.validate(mismatch)
        try:
            validate_fact(mismatch, PURE, schema, validator)
        except RuntimeError:
            pass
        else:
            fail("test gate accepted a self-declared SHA-256 of the wrong source")

        # Only reach here after real producer, real analyzer, strict refusals
        # and adversarial test input all completed successfully.
        print("REAL END-TO-END PASS (advisory only): {} producer -> v0 -> Rust".format(
            args.backend))
        print("reviewed producer={} analyzer={} contract={}".format(
            args.producer_head, args.analyzer_head, args.contract_head))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("E2E BLOCKED/FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
