# Oreslang Static Analysis — Rust

## AttoLang migration and current specification (2026-11-18)

**AttoLang** is the current language name, formerly **Oreslang**. This `ores-truffle-oreslang/oreslang-static-analysis.rs` checkout retains its historical name and documentation. The AttoLang-named destination for new related work is **[atto-lang/atto-static-analysis.rs](https://github.com/atto-lang/atto-static-analysis.rs)**. These are distinct GitHub repositories unless an exact verified migration establishes otherwise; do not assume identical code, issues, PRs, releases or test status.

**[atto-spec](https://github.com/atto-lang/atto-spec)** is the canonical normative language specification; old Oreslang-named specifications and examples are historical, not an independent authority. Use [atto-platform-conformance](https://github.com/atto-lang/atto-platform-conformance) for portable executable conformance, [atto-common-source](https://github.com/atto-lang/atto-common-source) for portable `.atto` libraries, and backend-specific `atto-source.*` for compiler/runtime implementations. The design direction includes `snake_case` methods, `borrow!`/`take!`/`share!`/`copy!`/`copy!!`, [implicit borrowing](https://github.com/atto-lang/atto-spec/blob/main/language/implicit-argument-borrow-v1.md), [file/module constants with one-time nonthrowing environment reads](https://github.com/atto-lang/atto-spec/blob/main/language/file-module-const-v1.md) and the [bitwise/stream operator proposal](https://github.com/atto-lang/atto-spec/blob/main/language/bitwise-and-stream-operators-v1.md). **These are targets, not proof that this checkout executes them.**

Existing `.ores`, `oreslang-*` tool commands, package/ABI names and fixture syntax below document legacy compatibility; only replace them after real target-specific compiler/runtime tests. Avoid Python tooling/tests in AttoLang projects; prefer Rust for supporting tooling. For backend feature claims, require exact source SHA/tree, target/toolchain, actual positive and negative guest execution, and explicit passed/failed/unsupported/not-executed status. Host-only and zero-step CI runs do not establish parity.

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
