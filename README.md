> **AI agent instructions (organization-wide):** Before working on code, issues, or pull requests, read and follow the [organization `AGENTS.md`](https://github.com/atto-lang/.github/blob/main/AGENTS.md), including its **merge-first stealth-development policy**. Honor any repository-local `AGENTS.md`, explicit holds, and GitHub-enforced rules.

# atto-static-analysis.rs

Static analysis and source diagnostics for AttoLang programs.

## Naming migration and language authority

This repository is maintained at [atto-lang/atto-static-analysis.rs](https://github.com/atto-lang/atto-static-analysis.rs); use `https://github.com/atto-lang/atto-static-analysis.rs.git` for Git remotes and canonical `.atto` source examples. The normative language contract is [atto-spec](https://github.com/atto-lang/atto-spec), with executable guest evidence tracked by [atto-platform-conformance](https://github.com/atto-lang/atto-platform-conformance). Follow current ownership, borrowing, effects, actor, and syntax rules there; do not infer implemented features from a README or unexecuted CI.

## Purpose

Analyze source semantics, ownership violations, and cross-backend diagnostics.

## Repository responsibilities

- Keep interfaces, schemas, and behavior documented in a backend-neutral form where applicable.
- Use test fixtures and reproducible evidence to distinguish proposed behavior from implemented behavior.
- Record breaking changes, migration notes, and dependencies on other AttoLang components.

## Validation

Validation should rely on checked-in tests and exact-commit CI results. When reporting parity, distinguish **passed**, **failed**, **unsupported**, and **not executed**. Avoid inferring guest-runtime support from host-only tests.

## Status and development

This README records the intended role of this repository; it is not a claim of feature completeness. Consult the source tree and workflow files for actual implementation and verified build commands. Contributions should preserve compatibility with the canonical language contract.

## Ecosystem

- [AttoLang](https://github.com/atto-lang)
- [Language specification](https://github.com/atto-lang/atto-spec)
- [Cross-platform conformance](https://github.com/atto-lang/atto-platform-conformance)

## Repository ownership and contribution routing

**Belongs here:** Static source analysis, lint rules, source-level diagnostics, ownership/effect checks and deterministic finding formats.

**Belongs elsewhere:** Canonical rule definitions belong in atto-spec; emitting target code belongs in compiler repos; code formatting belongs in atto-format.

**Security and portability boundary:** No autofix may introduce implicit conversions or mutate ownership. Include safe/unsafe negative fixtures, precise spans, false-positive regressions and no host execution of analyzed code.

AttoLang is the canonical project name; new source, examples and documentation use `.atto` and the `atto-lang` repository organization. This README defines scope, not feature readiness.

**Acceptance:** name the exact source SHA/tree, runtime/toolchain, positive and negative checks and execution receipt before claiming support. Host-only tests and empty CI steps do not prove guest execution.

## Source preflight (draft)

The `src/lib.rs` preflight is a dependency-free **lexical input gate**, not a
parser or proof of compiler support. It rejects inputs above 1 MiB, NUL bytes,
nested block comments deeper than 1,024, and unterminated comments or quoted
literals. Diagnostics carry zero-based UTF-8 byte offsets and one-based lines
and byte columns (not UTF-16 editor positions).

Run `cargo test --offline --all-targets` with a Rust toolchain. No code from
the analyzed source is executed. Template interpolation, semantic ownership,
types and target-specific admission remain the compiler's responsibility.
