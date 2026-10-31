# Oreslang safety admission v1 (Rust engine)

The command \`ores-analyze --safety envelope.json hard\` consumes a structured, versioned **MIR effect trace**. It does not parse Oreslang source, nor does it validate that a compiler emitted complete effects. It is therefore **not** a general proof of Oreslang memory safety, freedom from deadlock, or hard real-time behavior.

## Gates implemented now

| Area | Initial checks | Proof gap |
|---|---|---|
| Ownership | linear owned places; move consumes place; reads/writes require owned value | CFG joins, projections, provenance, NLL and alias analysis |
| Borrowing | shared/exclusive conflict, unique loan IDs, use-after-move, no moves during loans, no loans escaping functions | paths, closures, interprocedural lifetimes, pinning, field splitting |
| Actor ownership | reject mutable actor transfer; reject immutable transfer without an explicit freeze/trust-domain proof | actor-owned arenas, immutable sharing, capability provenance |
| Deadlock hazards | per-function lock balance, nesting, lock-order dependency DAG across functions, reject cycles/reentrance/wait under lock | dynamic locks, channels, message-level waits, distributed deadlock, actor state locks |
| Cooperative scheduling | abstract cost budget between `cooperate`/suspend checkpoints; reject cooperative yields with live loans, locks, or critical regions | compiler-inserted watchdog, machine instructions, real timing, pinned-continuation provenance |
| Error handling | named fallible effects must be caught or explicitly propagated; no bare panic | typed Error hierarchy, catch/raise/unwind CFG, supervisor contracts |
| Soft RT | static cooperative budget, no unbounded waits, explicit allocation boundaries | pauses, GC, scheduler and OS latencies |
| Hard RT | preliminary static gate for no allocations, bounded work, no unverified FFI | target WCET, stack depth, scheduling/priority inversion, RT OS, hardware/interrupt evidence |

\`hard_realtime_certified\` is always **false** in this version. Passing the static gate means only that the analyzed **linear IR trace** has no errors under the listed checks. An independently validated compiler emitter, function/CFG coverage, FFI contracts, target-specific WCET evidence, bounded stack, platform model and scheduler proof are still required before making a hard-RT claim.

## Untrusted input and analyzer work budgets

Every CLI entrypoint reads at most its byte limit plus one byte from both
regular files and standard input. File metadata is **not** a security boundary:
special files can report size zero, and ordinary files can grow during a read.

| Input mode | Maximum input bytes |
|---|---:|
| `--cfg`, `--static-facts` | 1 MiB |
| `--flow` | 4 MiB |
| `--safety`, default effect IR | 8 MiB |
| `--layout` | 16 MiB |

The linear `--safety` engine also rejects empty modules, more than 4,096
functions, more than 100,000 total events, and function names longer than
256 UTF-8 bytes, including when invoked directly as a Rust library.
Diagnostics `ORES-SAF004` (manifest size) and `ORES-SAF002` (function
identity) are admission failures. The CFG-v2 engine additionally rejects
modules above 4,096 total basic blocks or 100,000 total events with
`ORES-CFG010` before starting state propagation; per-function limits still
apply independently.

Global lock-order cycle detection in both safety and CFG modes is
**iterative**, so long attacker-controlled acyclic chains cannot exhaust the
Rust call stack. Safety mode retains a deterministic cycle counterexample;
the CFG mode uses a topological walk. Regression cases exercise a 10,000-edge
chain with and without a closing cycle edge. The analyzers also reject lock
nesting beyond 64 and count at most 16,384 attempted lock-order pairs globally
(`ORES-SAF205`, `ORES-CFG206`). Repeated/across-function attempts count
even when the resulting edge already exists, so graph construction itself
remains bounded. The fail-closed policy does not imply dynamic deadlock
freedom.

The CFG-v1 flow checker now aborts without traversing functions when the
module header/schema is invalid or the function count exceeds 4,096;
this preserves `ORES-FLOW001`/`ORES-FLOW002` rejection with bounded
follow-up work.

**Cooperative checkpoint parity (2026-10-31):** Each analyzer currently treats
`cooperate` as a potentially suspending scheduler operation. Without
independent pinned-frame/loan-lifetime proof, it must not reset an abstract
work budget while any borrow/loan, acquired lock, or actor-state critical
region is live. Linear safety returns `ORES-SAF303`; CFG-v2 returns
`ORES-CFG202`; flow-v1 returns `ORES-FLOW203`. Tests cover denial while
active and successful cooperation after ending a borrow.

This conservative rule may be relaxed by a future verified pinned-continuation
contract; it is not a proof that the compiler emitted complete source effects.
The CLI fixture `examples/flow-critical-cooperate-invalid.json` must exit
**exactly 1**, include `ORES-FLOW203` and report
`hard_realtime_certified=false`. A parse error (exit 2) does not pass the gate.

**Unverified critical-region provenance:** The flow-v1 `critical_enter`
and `critical_leave` markers contain only a text ID; they do not encode
`critical-read` vs `critical-write`, owning actor identity, or a
sealed-state capability. A balanced pair must therefore remain
**non-admissible** (`ORES-FLOW204`) even when no checkpoint occurs inside it.
The nesting and suspension checks still run to provide useful diagnostics.
Only a future typed contract with independently authenticated lowering and
capability provenance can promote these operations to static admission.

**Work-cost consistency:** An explicit `compute(units=0)` event is rejected
in every profile, rather than being treated as proof of completed work.
Safety/CFG/flow report `ORES-SAF304`, `ORES-CFG303`, and
`ORES-FLOW303` respectively. This is consistent with the effect-v1
engine's zero-work rejection. Positive fixtures continue using real
positive abstract units; synthetic statements of zero work cannot be used
to fabricate a cooperative budget.


Cross-organization private-source mirroring remains **blocked independently
of runner capacity** pending the Oreslang source-transfer incident and
authorization gates (conformance issues #22, #77, #127 and #212).
Source-free private runner admission can prove scheduling availability only,
not permission to publish this repo's contents to a test carrier.

These limits bound parsing/analysis work;
they do **not** prove that a producer has enumerated all source effects.
A self-asserted `effects_complete: true` must never be interpreted as
independently authenticated compiler provenance.

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
