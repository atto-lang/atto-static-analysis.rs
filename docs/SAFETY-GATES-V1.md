# Oreslang safety admission v1 (Rust engine)

The command \`ores-analyze --safety envelope.json hard\` consumes a structured, versioned **MIR effect trace**. It does not parse Oreslang source, nor does it validate that a compiler emitted complete effects. It is therefore **not** a general proof of Oreslang memory safety, freedom from deadlock, or hard real-time behavior.

## Gates implemented now

| Area | Initial checks | Proof gap |
|---|---|---|
| Ownership | linear owned places; move consumes place; reads/writes require owned value | CFG joins, projections, provenance, NLL and alias analysis |
| Borrowing | shared/exclusive conflict, unique loan IDs, use-after-move, no moves during loans, no loans escaping functions | paths, closures, interprocedural lifetimes, pinning, field splitting |
| Actor ownership | reject mutable actor transfer; reject immutable transfer without an explicit freeze/trust-domain proof | actor-owned arenas, immutable sharing, capability provenance |
| Deadlock hazards | per-function lock balance, nesting, lock-order dependency DAG across functions, reject cycles/reentrance/wait under lock | dynamic locks, channels, message-level waits, distributed deadlock, actor state locks |
| Cooperative scheduling | abstract cost budget between \`cooperate\`/suspend checkpoints, unknown costs rejected | compiler-inserted watchdog, machine instructions, true execution times, loop/branch CFG |
| Error handling | named fallible effects must be caught or explicitly propagated; no bare panic | typed Error hierarchy, catch/raise/unwind CFG, supervisor contracts |
| Soft RT | static cooperative budget, no unbounded waits, explicit allocation boundaries | pauses, GC, scheduler and OS latencies |
| Hard RT | preliminary static gate for no allocations, bounded work, no unverified FFI | target WCET, stack depth, scheduling/priority inversion, RT OS, hardware/interrupt evidence |

\`hard_realtime_certified\` is always **false** in this version. Passing the static gate means only that the analyzed **linear IR trace** has no errors under the listed checks. An independently validated compiler emitter, function/CFG coverage, FFI contracts, target-specific WCET evidence, bounded stack, platform model and scheduler proof are still required before making a hard-RT claim.

## Command & semantics

\`\`\`sh
cargo test --locked --workspace --all-targets
cargo run --locked -p ores-analyze -- --safety examples/safety-valid.json hard
cargo run --locked -p ores-analyze -- --safety examples/safety-invalid.json hard  # should fail
\`\`\`

Exit statuses: \`0\` admitted to these limited static gates; \`1\` rejected; \`2\` invalid CLI or malformed JSON. Reports include machine-readable error codes and event indices. \`effects_complete: true\` is an untrusted source assertion; it is not a certification mechanism. Malicious or incomplete producers can invalidate the results.

## Next implementation, in strict order

1. Replace linear event trace with validated SSA/CFG IR with block IDs, edge verification, source spans and complete exhaustiveness; run flow-sensitive dataflow at joins.
2. Add place projections, region origins/outlives, reborrows, loan kills, suspending borrows and capability-aware actor transfer; use Rust's Polonius model conceptually without using Rust's borrow checker as Oreslang's semantics.
3. Compose summaries interprocedurally with conservative recursion bounds; model awaited actors, channels/select, scheduler queues, worker pools and blocking libraries.
4. Add async state machines, error unwind edges, panic/supervision effects, \`trap\`, Result and Option exhaustiveness.
5. Calibrate cooperative abstract budgets to target-specific WCET/interrupt/scheduler evidence and force fail-closed policy for untrusted JIT code and GC.
6. Run Java, C++/LLVM and Rust producers against the exact same safety fixtures; assert diagnostic class parity, then add independently verified runtime stress tests.

## Explicit principles

No source-level construct may disappear between AST -> typed HIR -> safety MIR -> optimized MIR -> Cranelift/LLVM/Graal without a revalidated effect summary. Hard-RT certification is separate from AOT compilation. Static-analysis claims are bounded to a declared language fragment, target and assumptions.
