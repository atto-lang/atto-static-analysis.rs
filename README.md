# Oreslang Static Analysis — Rust

Cross-backend, structured analysis for Oreslang. Independent of GraalVM and LLVM.

## Working prototype

The first checkable contract is a **versioned JSON effect IR**. Java, C++/LLVM, and Rust can emit the same input without sharing private repository code or linking different compilers.

\`\`\`sh
cargo test --workspace
cargo run -p ores-analyze -- examples/hard-realtime.json hard
cargo run -p ores-analyze -- examples/unsafe.json hard
\`\`\`

The CLI prints machine-readable JSON diagnostics, summaries, and uses a nonzero exit code for errors. Source spans, lints, LSP/SARIF and native Oreslang parsing are next; this milestone does **not** claim a full proof of hard real-time behavior.

See [architecture](docs/ARCHITECTURE.md) and [versioned input contract](docs/IR-V1.md).

## Repository ownership and migration (2026-11-08)

**AttoLang** is the public language name; this repository remains `ores-truffle-oreslang/oreslang-static-analysis.rs` until an authorized move. Keep existing `oreslang-*` CLI/package conventions and supported `.ores` files compatible. **Belongs here:** Rust static analysis tools and reviewable source diagnostic rules. **Does not belong here:** compilation semantics duplicated outside real backend validation.

**Organization model:** [`atto-lang`](https://github.com/atto-lang) hosts language syntax, compilers, portable core/std, tooling, conformance, ecosystem libraries and demos. [`atto-co`](https://github.com/atto-co) hosts separately governed deployment, tenant runtime, identity, registry, billing and managed cloud infrastructure. The existence of a related `atto-*` repo is not evidence this repository was transferred or that its code and tests are equivalent.

**Proposed first transfer:** `atto-lang/oreslang-static-analysis.rs`, retaining the same GitHub numeric repo identity and old name; this is not a completed transfer or an approved direct move into `atto-co`. Future AttoCo carve-outs require their own security/release approvals. Coordinate with [source-org migration issue #26](https://github.com/ores-truffle-oreslang/.github/issues/26) and the private [migration draft #25](https://github.com/ores-truffle-oreslang/.github/pull/25). Before an authorized transfer: record exact head SHA and Git tree, numeric ID, permissions/visibility, branch rulesets, reviewers, open PRs, dependencies, package identifiers, release tags, secrets, webhooks, GitHub Apps, CI and rollback owner; require source/target admin plus independent security review. Never mirror private code to bypass transfer authorization. After moving, verify repository ID/history and controls, fix consumers and rerun **nonzero-step exact-head tests**. `steps=[]`/`null` is `NOT_EXECUTED`; host-only/static tests do not certify compiled AttoLang guest behavior.
