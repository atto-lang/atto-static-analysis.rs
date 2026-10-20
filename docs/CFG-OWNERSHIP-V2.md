# Experimental CFG v2 ownership and effect admission

\`ores-analyze --cfg examples/cfg-valid.json hard\` accepts a versioned CFG envelope containing basic blocks, explicit edges, scalar owned places, borrow-loan events and bounded abstract compute effects. An invalid branch/move path can be rejected with structured error codes.

## What v2 actually proves (within its modeled fragment)

- Every declared block is reachable from the declared entry; no missing/duplicate successors or block IDs; all loop backedges/cycles rejected **until** independent loop bounds exist.
- Definite ownership joins use a must-owned meet: moved on *any* incoming path means unavailable following a join.
- Active loans, outstanding error effects and held locks must match across joins. This rejects ambiguous lifetimes rather than silently discharging them.
- Both branches participate in max-path abstract work-cost admission; cooperative reset is explicit.
- Lock order graph is checked for cycles across functions, with rejects for lock-held waits, suspension or cooperative yields.
- Calls, actor transfers, unchecked FFI and panic are not assumed safe. Fallible effects must be caught or intentionally propagated.
- The \`hard_realtime_certified\` response field is ALWAYS \`false\`, even for accepted \`hard\` inputs.

## What v2 does *not* prove

This is a **scalar-place, acyclic CFG prototype**, not a full typed SSA, Rust-grade nonlexical-lifetime borrow checker or complete Oreslang validator. No field projections, typed alias classes, reborrows, disjoint-field checking, general loops, interprocedural summaries, actor wait graph, Task quiescence, exception/unwind CFG, sound source provenance, stack/GC bounds or hardware WCET proof. \`effects_complete: true\` is an untrusted producer assertion, not an authenticated certificate.

Keep MIR emission strictly downstream of a validated typed HIR. Require independent proof that no source-level effect disappeared under optimizations. Older \`--safety\` linear IR is unchanged; CFG-v2 lives behind \`--cfg\` for differential testing.

## CI

\`\`\`bash
cargo test --locked --workspace --all-targets
cargo run --locked -p ores-analyze -- --cfg examples/cfg-valid.json hard
! cargo run --locked -p ores-analyze -- --cfg examples/cfg-invalid.json hard
\`\`\`

Every future expansion should introduce an invalid (adversarial) fixture before accepting a new MIR node. In particular: conditional borrows, exceptional exits, await/select, owned arena transfers, and branch-sensitive mutation.
