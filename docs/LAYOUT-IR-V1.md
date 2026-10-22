# Data-layout advisory IR v1

The layout IR is a separate, advisory contract for data-oriented optimization. It does not participate in safety or real-time admission and does not prove speedups, SIMD legality, cache behavior, actor isolation, or memory safety.

Run the analyzer with:

    cargo run -p ores-analyze -- --layout examples/layout.json

The top level contains schema_version, evidence_complete, target, and regions. evidence_complete must be true or the analyzer fails closed and emits no optimization findings. target contains optional cache_line_bytes and vector_bytes values; known values must be powers of two and at least 8 bytes.

Each region contains name, scope, layout, rows, field_bytes, accessed_fields, dense_iteration, sequential_rows, hot, relocation_verified, stable_address_required, whole_record_access, iteration_independent, sparse_membership, independent_component_passes, and concurrent_mutable_sharing.

scope is one of core, stdlib, runtime, or userland. layout is one of aos, soa, aosoa, sparse_set, or archetype. rows may be null when cardinality is unknown. accessed_fields are distinct zero-based indexes into field_bytes.

Finding families:

* ORES-LAYOUT101 through ORES-LAYOUT103: SoA opportunity, relocation-not-verified case, or a transform suppressed by semantic constraints.
* ORES-LAYOUT111: AoSoA benchmark candidate when sequential independent access and a target vector width make tiling plausible.
* ORES-LAYOUT121 through ORES-LAYOUT122: ECS, sparse-set, or archetype candidate, including blocked candidates.
* ORES-LAYOUT201: possible false sharing that requires target-specific profiling.
* ORES-LAYOUT301: non-sequential locality or pointer-chasing risk.

Stable-address requirements and whole-record access suppress layout rewrite recommendations. Missing relocation proof produces a blocked finding rather than a safe rewrite recommendation. ECS advice requires sparse membership and independently selectable component passes. AoSoA tile rows are only a benchmark starting point.

Resource limits are part of the v1 analyzer contract: layout JSON is capped at 16 MiB by the CLI; the analyzer caps regions at 10000, fields or accessed-field entries per region at 16384, total field/access evidence at 1000000 items, and region names at 1024 UTF-8 bytes.

All findings are advisory. The byte counts in the report come from declared schema widths and are not measurements of cache misses, DRAM traffic, vector occupancy, instructions, cycles, or WCET.
