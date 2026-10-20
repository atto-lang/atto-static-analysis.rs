#!/usr/bin/env bash
# Exact-source Java -> Rust analyzer smoke for locally authorized checkouts.
# Usage: bash scripts/test-java-static-facts-roundtrip.sh /path/to/oreslang-source.java
set -euo pipefail
if [[ "$#" -ne 1 ]]; then echo "Pass the Java source checkout path" >&2; exit 2; fi
JAVA_ROOT="$(cd "$1" && pwd)"
RUST_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v mvn >/dev/null || { echo "Maven required" >&2; exit 2; }
command -v cargo >/dev/null || { echo "Cargo required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "Python required" >&2; exit 2; }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

cat > "$scratch/recursive.ores" <<'ORES'
fnc again(int x): int { return again(x); }
pub routine main(): int { return again(5); }
ORES

cat > "$scratch/scalar.ores" <<'ORES'
pub routine main(): int { return 42; }
ORES

(
  cd "$JAVA_ROOT"
  mvn -q -Dtest=StaticFactsV0ExporterTest,StaticFactsCliTest test
  mvn -q -DskipTests compile exec:java     "-Dexec.args=--static-facts $scratch/recursive.ores"     > "$scratch/recursive.json"
  mvn -q -DskipTests compile exec:java     "-Dexec.args=--static-facts $scratch/scalar.ores"     > "$scratch/scalar.json"
)

python3 - "$scratch" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
for name in ("recursive", "scalar"):
    source = (root / (name + ".ores")).read_bytes()
    actual = json.loads((root / (name + ".json")).read_text())
    assert actual["version"] == "ores-static-facts/v0"
    assert actual["unit"] == "sha256:" + hashlib.sha256(source).hexdigest()
    assert actual["taint_sources"] == []
    assert actual["flows"] == []
    assert actual["sinks"] == []
    assert actual["permission_checks"] == []
print("Java typed-AST exact-byte identity: PASS")
PY

(
  cd "$RUST_ROOT"
  cargo test --locked -p ores-analysis shared_facts
)
set +e
(
  cd "$RUST_ROOT"
  cargo run --locked -q -p ores-analyze --     --static-facts "$scratch/recursive.json" general > "$scratch/recursive-report.json"
)
recursive_status=$?
set -e
if [[ "$recursive_status" -ne 1 ]]; then
  echo "Expected a nonzero recursion finding; got $recursive_status" >&2
  exit 1
fi

(
  cd "$RUST_ROOT"
  cargo run --locked -q -p ores-analyze --     --static-facts "$scratch/scalar.json" general > "$scratch/scalar-report.json"
)

python3 - "$scratch" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
recursive = json.loads((root / "recursive-report.json").read_text())
scalar = json.loads((root / "scalar-report.json").read_text())
assert recursive["producer_authenticated"] is False
assert recursive["advisory_only"] is True
assert recursive["work_allocation_copy_bounds"] == "unverified"
assert any(d["code"] == "ORES-SA102" for d in recursive["report"]["diagnostics"])
assert not any(d["code"] == "ORES-SA102" for d in scalar["report"]["diagnostics"])
assert all(s["allocations_upper_bound"] is None
           for s in scalar["report"]["functions"].values())
print("Java .ores -> common v0 JSON -> Rust scalar analyzer: PASS (advisory only)")
PY
