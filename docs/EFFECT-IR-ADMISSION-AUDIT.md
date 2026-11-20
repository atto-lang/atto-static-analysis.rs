# Untrusted effect-IR admission on current main

Both analyzer modes remain available:

- `ores-analyze INPUT hard`: effect IR v1 (`Program`)
- `ores-analyze --safety INPUT hard`: typed safety MIR (`SafetyProgram`)

The CLI limits JSON input to 8 MiB (including stdin), before
deserialization. The effect mode preflights function count, nesting,
operation count, call symbol length and recursive call depth. It
rejects `compute(units=0)`, unverified suspension in strict hard RT,
unsafe cross-actor mutation, unknown calls and recursion. Zero-trip
loops do not execute nested missing/unsafe calls.

Every effect-mode `Report` now explicitly says
`"assurance_level":"untrusted_effect_ir_model_only"`.
A successful `hard` response is **not** a real-time certificate:
source producer identity, target codegen, stack/WCET, interrupt timing,
dependencies and physical runtime behavior are not verified.

The new security checks are additive to `src/safety.rs`, which is
preserved unchanged. The compiler forward-call fixture must remain
compatible, including abstract work count of 6 for `main`.

Verification once a runner/toolchain is available:

```bash
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo run --locked -p ores-analyze -- examples/forward-from-rust-compiler.json hard
cargo run --locked -p ores-analyze -- --safety examples/safety-valid.json hard
```
