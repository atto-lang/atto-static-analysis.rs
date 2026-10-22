# Cross-language SoA / AoSoA / ECS static-analysis program

## Goal and implementation split

Oreslang should diagnose *suboptimal* storage and data-oriented access in
core, alloc, stdlib, runtime and user applications, not merely ensure that a
layout is well-typed. Use one shared, conservative advisory diagnostic contract
(`ORES-LAYOUT*`) and architecture-specific facts from **typed** passes.

| Analyzer/producer | Current practical role | Next integration |
| --- | --- | --- |
| Rust (`oreslang-static-analysis.rs`) | Canonical versioned layout IR and evidence-gated advisory engine; codes 101, 111, 121, 131–135, 201, 301 | Consume typed MIR access summaries and PGO, emit SARIF with source spans |
| Oreslang compiler Java | Host-side typed evidence and diagnostic prototype `DataLayoutAdvisor` | Extract actual field accesses, loops and handle/alias constraints from Java compiler HIR |
| Oreslang compiler LLVM/C++ | Host-side `DataLayoutAdvisor.hpp`; exact `DopLayout::Plan` padding check (141) | Feed Oreslang typed CFG/DOP loops, model AoSoA vector instruction legality |
| Rust native compiler (`oreslang-source.rs`) | Scalar HIR/MIR effect export, not yet DOP field pass | Record field access/loop nests once inverted classes/regions compile |
| Oreslang-native analyzer | **Planned, not self-hosted or executable today** | Implement the same rules in optional `stdlib/analysis` after Oreslang compiler and typed metaprogramming APIs are ready |

Rust, Java and C++ refer here to **implementation languages**. The primary
source language analyzed is Oreslang. Static analysis of arbitrary Rust, Java
and C++ *host source code* requires the respective language's parsed
semantic AST/HIR (e.g. rustc/Clippy, javac, Clang tooling); regular-expression
source scans cannot establish field escape, aliasing, iteration dependence or
hotness and must not set `evidence_complete=true`.

## One region per access pass, not per type

The same type may be optimal as AoS in one pass and SoA in another.
Collect for each type/function/pass: validated field widths, layout, row
cardinality bound, accessed field set, dense/sequential flags, whole-record
materialization, target vector/cache widths, observed hotness, and exact source
symbol/file/line. Record unknown facts as `null`. Profiles may produce a
separate IR input; never merge contradictory workloads into fake evidence.

Extra facts for high-value diagnostics:
- physical AoSoA tile rows, tail occupancy and actual bytes (geometry can
  prove excess capacity, **not** speed)
- observed random cross-column gathers and cache/TLB counters
- actual ECS structural changes (insert/delete/archetype migration) per pass
- independently selectable components and stable/dense membership
- ownership/borrow, generation-handle, actor allocation domain and relocation
  eligibility, before proposing a candidate rewrite

## Heuristics and proof boundaries

- High-confidence *correctness*: geometry validation, out-of-range field
  access, inconsistent evidence, bound overflow. Reject rather than advise.
- Medium/low-confidence *performance hypotheses*: field-selective AoS => SoA;
  whole-record SoA => AoS/AoSoA; dense stable ECS => fused traversal;
  repeated random gathers; AoSoA tile-vs-SIMD mismatch; frequent structural
  mutation => command buffer / batched migration; cache-line sharing risk.
- Check separately: ECS sparse-set vs archetype migration and query selectivity,
  SIMD alignment/masks, AoSoA tails, AoS hot/cold splitting, padding, cache-line
  false sharing, SoA map lookups, pointer chasing, redundant scatter/gather,
  temporary AoS snapshots, per-frame allocations, stability of handles.
- **No automatic transforms yet.** Do not clone AoS, SoA and AoSoA into
  synchronized stores. Keep one authoritative layout per allocation/store and
  require region/actor ownership proofs for any migration.
- No analyzer output is WCET, energy, allocation-free, SIMD or actor-isolation
  certification. Confirm performance by differential microbenchmarks,
  representative workload profiling, and target-specific runtime counters.

## Run the current Rust evaluator

```sh
cargo run -p ores-analyze -- --layout examples/layout.json
cargo run -p ores-analyze -- --layout examples/layout-antipatterns.json
cargo test --workspace
```

`examples/layout-antipatterns.json` is **synthetic workload evidence** to
exercise rules; it does not claim those exact source sites are slow. 
At least one invalid region suppresses **all** optimization findings from
the document. For a real codebase, produce JSON from typed compiler and
profile facts first; attach the exact source span (never infer it from a region
name).

## Staged adoption

1. Bring Rust advisor #7 and follow-up to green test status.
2. Connect Java and C++ typed frontend/layout metadata to the exact
   versioned IR (no standalone policy divergence).
3. Add compiler differential fixtures: same Oreslang source/access patterns
   => identical diagnostic codes and source spans across native/JVM backends.
4. Add PGO/hardware counters and calibrated rule thresholds.
5. Build the same immutable semantic analysis in Oreslang and self-host it
   under optional stdlib/analysis, while `core` stays freestanding/no-alloc.

No stage should change safety policy because an optimization heuristic fired.

## Source-level bridge now implemented (Java/Oreslang AST, draft PR #1621)

`OresCompiler.inspectLayoutAccesses(String source)` runs the real Java
Oreslang parser, type checker and ownership checker, then gathers bounded
member-syntax observations from supported `for-of` loops. It returns the
containing callable, iterable/binding names, distinct selected members, and
explicit unsupported/whole-row flags. This is **source-derived**, unlike
synthetic IR fixtures, but still incomplete for physical optimization.

The observation API explicitly returns
`completeForLayoutRecommendations=false` on every result. It must **not**
be serialized into a Rust `LayoutProgram` with `evidence_complete=true`.
A member expression may be a property rather than a physical field, and the
compiler has not proven a physical store, field offset/size, actor-domain
relocation, borrow lifetime, row count, hotness, or source span.

Next integration should join (a) the source observation,
(b) type-resolved physical field/store identity from Oreslang HIR, and
(c) independent target/profile evidence. Only then can a producer provide
complete, validated v1 regions to this Rust advisory engine.
