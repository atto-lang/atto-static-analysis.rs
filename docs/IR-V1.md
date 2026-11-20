# Effect IR v1 (prototype)

Top-level: \`{"schema_version":1,"functions":[...]}\`. Each function has a unique \`name\` and \`operations\`. Operation kinds and required fields match the tagged Rust \`Operation\` enum. All sizes and loop bounds are unsigned 64-bit values. A missing/null bound means **unknown**. Bounds saturate to unknown on overflow and never silently wrap.

\`allocate\` and \`copy\` are bytes, \`loop\` has \`iterations\` and child \`operations\`; \`call\` has \`target\`. \`blocking_io\`, \`unbounded_wait\`, \`suspend\`, \`unsafe_ffi\`, \`indirect_call\` are effect tags. \`share_mutable\` has \`crosses_actor_boundary\` (true is a soundness violation).

The current \`operations_upper_bound\` is an abstract number of effect nodes, **not** hardware instructions/cycles. An unknown callee, a recursive call cycle, or an indirect call is rejected in strict modes. Source spans, stable IDs, interprocedural receiver polymorphism, operation effects, rich state machines, loop invariants, call budgets and analyzer certificates will require a versioned IR upgrade.

Keep the producer contract executable: every backend must feed golden fixtures with equivalent summaries and error codes.


## Independent Rust frontend emitter (2026-10-19)

The independent Rust compiler exports this format with:

    oresc --effects tests/fixtures/forward.ores > effects.json
    ores-analyze effects.json hard

\`compute\` with non-null \`units\` represents bounded *abstract operations* for already-admitted scalar expressions. It does **not** represent instructions, cycles, energy, copies or a WCET certificate. Function calls remain explicit \`{"kind":"call","target":"callee"}\` entries, so the analyzer can compute conservative callgraph summaries and reject recursion without a separate bound. Consumers must not convert absence of observed effects in an incomplete producer into a runtime isolation proof.

Current v1 producer covers only statically resolved signed-i64 functions and immutably bound local constants. No dynamic dispatch, heap effects, actors, async, FFI or user-defined type operations are supported by that frontend, so its effect export cannot be applied to such constructs. Any future extension must fail closed until every new node has explicit effect semantics.
