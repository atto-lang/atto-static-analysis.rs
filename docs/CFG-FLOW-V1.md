# CFG admission prototype — flow IR v1

The Rust analyzer now has a separate CFG-sensitive ownership and effects checker:

    cargo run --locked -p ores-analyze -- --flow examples/flow-scalar-from-rust.json hard

## Scope

- Acyclic basic blocks; explicit Return, Jump or Branch terminators
- Strictly validated block identifiers, edges and reachability
- Finite path-sensitive work budgets using the *maximum* predecessor bound
- Identical moved/owned places, loans, domains and critical regions at joins (otherwise reject)
- Linear ownership, reader/writer borrow exclusivity, invalid moves/writes
- No live loans or critical regions at Task suspension or function return
- Actor domain transfer: serialized ownership moves versus prevalidated immutable capabilities

## Trust and correctness

This verifier consumes assertions from the compiler, including effects_complete and the declared domain. It **cannot** independently attest complete source lowering, freeze proofs, message serialization, allocation behavior, actor memory isolation, machine WCET or real-time certification. It returns hard_realtime_certified=false even for an admitted static contract. A branch-and-join validation is not yet a full dataflow framework for loops; cycles are rejected. Unknown interprocedural calls are rejected, never silently treated as pure.

Schema keys are required and unknown fields rejected. A hard profile requires explicit max_uninterrupted_units; compute units are *abstract operations*, not wall time. This prototype intentionally remains separate from the older linear --safety envelope until their invariants can be formally aligned.

## Integration

The Rust compiler's small scalar subset can emit a compatible flow envelope with:

    oresc --flow 6 tests/fixtures/flow-scalar.ores

The compiler exporter intentionally refuses function calls, actors and async. The Java/LLVM frontends must implement and test equivalent contract producers; no C++/Java implementation is claimed here.

## Security hardening (2026-10-19)

- All `actor_send` operations currently emit `ORES-FLOW108`, **including** those tagged `shared_immutable` or `serialized_move`. An asserted domain label is not a freeze/lifetime/authorization proof, and claiming serialization does not prove bounded copies or allocations. Admitting actor sends must wait for verified provenance and effect certificates, not a user-supplied Boolean.
- `soft` and `hard` profiles both reject unknown abstract compute work and missing uninterrupted-work limits. Admission is a *modeled* static gate, not a timing certification.
- Across the entire CFG payload (not per-function only), the prototype limits blocks to 4,096 and events to 100,000. The CLI reads no more than 4 MiB of input plus one byte, then fails closed for oversized files or standard input.
- JSON from untrusted producers remains non-authoritative: `effects_complete: true` is a compiler attestation, not proof that omitted instructions, FFI, suspension or effects do not exist.

## Interprocedural scalar call summaries (stacked milestone)

`call` events can be statically admitted only when their target and every
transitive callee can be independently summarized as a **single-block,
pure scalar** function with finite compute units, local declarations/reads,
and direct scalar calls. The analyzer memoizes each bound, adds one abstract
unit per call dispatch, and rejects recursion (including mutual recursion),
unresolved/ambiguous targets, overflow, state mutation, ownership transfers,
allocation, FFI, suspension, cooperative resets, and nontrivial callee CFGs.
No general-purpose call safety or WCET certificate is claimed. The caller's
own budget includes the full transitive verified scalar work.
