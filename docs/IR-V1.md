# Effect IR v1 (prototype)

Top-level: \`{"schema_version":1,"functions":[...]}\`. Each function has a unique \`name\` and \`operations\`. Operation kinds and required fields match the tagged Rust \`Operation\` enum. All sizes and loop bounds are unsigned 64-bit values. A missing/null bound means **unknown**. Bounds saturate to unknown on overflow and never silently wrap.

\`allocate\` and \`copy\` are bytes, \`loop\` has \`iterations\` and child \`operations\`; \`call\` has \`target\`. \`blocking_io\`, \`unbounded_wait\`, \`suspend\`, \`unsafe_ffi\`, \`indirect_call\` are effect tags. \`share_mutable\` has \`crosses_actor_boundary\` (true is a soundness violation).

The current \`operations_upper_bound\` is an abstract number of effect nodes, **not** hardware instructions/cycles. An unknown callee, a recursive call cycle, or an indirect call is rejected in strict modes. Source spans, stable IDs, interprocedural receiver polymorphism, operation effects, rich state machines, loop invariants, call budgets and analyzer certificates will require a versioned IR upgrade.

Keep the producer contract executable: every backend must feed golden fixtures with equivalent summaries and error codes.


### Assurance and trusted producer boundary

All current analyzer reports include
`"assurance_level":"untrusted_effect_ir_model_only"`. The `hard` profile
checks only the supplied abstract effects. It **cannot** certify hard-real-time
execution or establish that a supplied JSON file corresponds to actual source.
Until authenticated source-to-IR and target-specific WCET are implemented, no
policy engine may treat a successful `hard` result as a certification token.

### Rust scalar-producer golden fixture

`examples/rust-scalar-expected.json` is byte-for-byte equal (ignoring
the trailing fixture newline) to the compiler's
`examples/scalar-effect-ir-v1.json`. The SHA-256 of the JSON bytes is
`8ee1adbf6faef704c1eb6d2b2075c3b2d723097037f646f9e6e518a69d005463`.
The expression `40+2` yields exactly three `compute(units=1)`
effects (two literals and one addition) and zero modeled allocations
or copies. This proves contract conformance for the narrow scalar subset,
**not** provenance of arbitrary supplied JSON or target hard-real-time safety.
