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

## Legacy migration and verification gates

The historical predecessor was `ores-truffle-oreslang/oreslang-static-analysis.rs`. This repository is now maintained in `atto-lang`; naming or imported history does not establish preservation of the original numeric repository ID, code parity or compiler support. Preserve working legacy `.ores` inputs and historical package/CLI aliases until replacement paths have been verified; new source follows canonical `.atto` contracts.

Rust static analysis and reviewable source diagnostic rules belong here; compiler semantics must not be independently invented outside real backend validation. [atto-lang](https://github.com/atto-lang) owns language, tooling and portable libraries; [atto-co](https://github.com/atto-co) separately governs commercial deployment, tenant infrastructure, identity, registry and billing. Any further original-ID transfer or managed-product carve-out requires separate owner authorization. This document authorizes no direct legacy-org transfer to atto-co.

Before an actual transfer, coordinate through [migration issue #26](https://github.com/ores-truffle-oreslang/.github/issues/26) and authorized source/target administrators and independent security reviewers. Inventory repository numeric ID, exact head/tree, history, visibility, access, rulesets, open PRs, releases, packages, CI/runners, secrets, deploy keys, apps, webhooks, Pages, consumers and rollback ownership. Never mirror private source without authorization. Verify unchanged ID/history/tree and restored controls after transfer, then execute exact-head tests before changing consumer references. Zero-step CI is NOT_EXECUTED; host-only and source-free tests are not compiled guest evidence.
