//! Advisory data-oriented layout analysis for core, stdlib, runtime and userland code.
//!
//! Evidence is supplied by a compiler or profiler. Findings are optimization
//! hypotheses only: they do not prove a speedup, SIMD legality, cache behavior,
//! memory safety, actor isolation, or real-time admission.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const LAYOUT_SCHEMA_VERSION: u32 = 1;
const MAX_REGIONS: usize = 10_000;
const MAX_FIELDS_PER_REGION: usize = 16_384;
const MAX_TOTAL_FIELD_ITEMS: usize = 1_000_000;
const MAX_REGION_NAME_BYTES: usize = 1_024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutProgram {
    pub schema_version: u32,
    /// A producer must explicitly attest that the access evidence required by
    /// this schema is complete for every described region.
    pub evidence_complete: bool,
    pub target: Target,
    pub regions: Vec<Region>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Null means unknown. Non-null values must be powers of two.
    pub cache_line_bytes: Option<u32>,
    /// Null means unknown. Non-null values must be powers of two.
    pub vector_bytes: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub name: String,
    pub scope: Scope,
    pub layout: Layout,
    /// Null means the producer cannot establish a row/cardinality bound.
    pub rows: Option<u64>,
    /// Declared byte width of each logical field, in declaration order.
    pub field_bytes: Vec<u32>,
    /// Zero-based distinct field indexes touched by the analyzed hot pass.
    pub accessed_fields: Vec<u32>,
    pub dense_iteration: bool,
    pub sequential_rows: bool,
    /// Must come from explicit compiler/profile evidence, not a guess here.
    pub hot: bool,
    /// Ownership, aliasing, actor-domain, outstanding-borrow and handle
    /// stability checks permit relocation/repacking.
    pub relocation_verified: bool,
    /// True when external semantics require addresses of row objects to remain stable.
    pub stable_address_required: bool,
    /// True when the pass materializes/observes complete records, even if it
    /// also has field-selective accesses.
    pub whole_record_access: bool,
    /// Producer has ruled out loop-carried dependencies relevant to reblocking.
    pub iteration_independent: bool,
    /// Membership is sparse/optional across the logical entity population.
    pub sparse_membership: bool,
    /// Components are processed in independently selectable passes/queries.
    pub independent_component_passes: bool,
    /// Producer observed or proved concurrently written data sharing a region.
    pub concurrent_mutable_sharing: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Core,
    Stdlib,
    Runtime,
    Userland,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    Aos,
    Soa,
    Aosoa,
    SparseSet,
    Archetype,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub region: String,
    pub scope: Scope,
    pub code: &'static str,
    pub kind: &'static str,
    pub confidence: &'static str,
    pub message: String,
    pub advisory: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationIssue {
    pub region: Option<String>,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionSummary {
    pub scope: Scope,
    pub current_layout: Layout,
    pub rows: Option<u64>,
    pub record_bytes: u64,
    pub accessed_field_bytes: u64,
    /// Thousandths of the record payload touched by this pass (0..=1000).
    pub accessed_fraction_permille: u16,
    pub suggested_aosoa_tile_rows: Option<u32>,
    pub transform_suppressed_by: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LayoutReport {
    pub schema_version: u32,
    pub findings: Vec<Finding>,
    pub errors: Vec<ValidationIssue>,
    pub regions: BTreeMap<String, RegionSummary>,
}

impl LayoutReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

fn target_width_valid(value: Option<u32>) -> bool {
    value.is_none_or(|bytes| bytes >= 8 && bytes.is_power_of_two())
}

fn push_error(
    errors: &mut Vec<ValidationIssue>,
    region: Option<&str>,
    code: &'static str,
    message: impl Into<String>,
) {
    errors.push(ValidationIssue {
        region: region.map(str::to_owned),
        code,
        message: message.into(),
    });
}

fn add_finding(
    findings: &mut Vec<Finding>,
    region: &Region,
    code: &'static str,
    kind: &'static str,
    confidence: &'static str,
    message: impl Into<String>,
) {
    findings.push(Finding {
        region: region.name.clone(),
        scope: region.scope,
        code,
        kind,
        confidence,
        message: message.into(),
        advisory: true,
    });
}

fn relocation_blockers(region: &Region) -> Vec<&'static str> {
    let mut blockers = Vec::new();
    if !region.relocation_verified {
        blockers.push("relocation_not_verified");
    }
    if region.stable_address_required {
        blockers.push("stable_address_required");
    }
    if region.whole_record_access {
        blockers.push("whole_record_access");
    }
    blockers
}

pub fn analyze_layout(program: &LayoutProgram) -> LayoutReport {
    let mut report = LayoutReport {
        schema_version: LAYOUT_SCHEMA_VERSION,
        findings: Vec::new(),
        errors: Vec::new(),
        regions: BTreeMap::new(),
    };

    if program.schema_version != LAYOUT_SCHEMA_VERSION {
        push_error(
            &mut report.errors,
            None,
            "ORES-LAYOUT001",
            "unsupported layout IR schema version",
        );
        return report;
    }
    if !program.evidence_complete {
        push_error(
            &mut report.errors,
            None,
            "ORES-LAYOUT002",
            "layout/access evidence is not marked complete; optimization advice suppressed",
        );
        return report;
    }
    if program.regions.len() > MAX_REGIONS {
        push_error(
            &mut report.errors,
            None,
            "ORES-LAYOUT004",
            format!("region count exceeds analysis budget of {MAX_REGIONS}"),
        );
        return report;
    }
    let total_field_items = program.regions.iter().try_fold(0_usize, |total, region| {
        total
            .checked_add(region.field_bytes.len())?
            .checked_add(region.accessed_fields.len())
    });
    if total_field_items.is_none_or(|count| count > MAX_TOTAL_FIELD_ITEMS) {
        push_error(
            &mut report.errors,
            None,
            "ORES-LAYOUT005",
            format!("field/access evidence exceeds analysis budget of {MAX_TOTAL_FIELD_ITEMS} items"),
        );
        return report;
    }
    if !target_width_valid(program.target.cache_line_bytes)
        || !target_width_valid(program.target.vector_bytes)
    {
        push_error(
            &mut report.errors,
            None,
            "ORES-LAYOUT003",
            "target cache/vector widths must be null or powers of two >= 8 bytes",
        );
        return report;
    }

    let mut names = HashSet::new();
    for region in &program.regions {
        if region.name.len() > MAX_REGION_NAME_BYTES {
            push_error(
                &mut report.errors,
                None,
                "ORES-LAYOUT006",
                format!("region name exceeds {MAX_REGION_NAME_BYTES} UTF-8 bytes"),
            );
            continue;
        }
        if region.field_bytes.len() > MAX_FIELDS_PER_REGION
            || region.accessed_fields.len() > MAX_FIELDS_PER_REGION
        {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT007",
                format!("region field/access list exceeds per-region budget of {MAX_FIELDS_PER_REGION}"),
            );
            continue;
        }
        if region.name.trim().is_empty() {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT010",
                "region name must not be blank",
            );
            continue;
        }
        if !names.insert(region.name.clone()) {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT011",
                "duplicate region name",
            );
            continue;
        }
        if region.field_bytes.is_empty() || region.field_bytes.iter().any(|bytes| *bytes == 0) {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT012",
                "field_bytes must contain at least one non-zero field width",
            );
            continue;
        }

        let mut indexes = HashSet::new();
        let mut accessed_bytes = 0_u64;
        let mut bad_access = false;
        for index in &region.accessed_fields {
            if !indexes.insert(*index) {
                push_error(
                    &mut report.errors,
                    Some(&region.name),
                    "ORES-LAYOUT013",
                    format!("duplicate accessed field index {index}"),
                );
                bad_access = true;
                break;
            }
            let Some(width) = region.field_bytes.get(*index as usize) else {
                push_error(
                    &mut report.errors,
                    Some(&region.name),
                    "ORES-LAYOUT014",
                    format!("accessed field index {index} is out of bounds"),
                );
                bad_access = true;
                break;
            };
            accessed_bytes = accessed_bytes.saturating_add(u64::from(*width));
        }
        if bad_access {
            continue;
        }
        if region.hot && region.rows != Some(0) && region.accessed_fields.is_empty() {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT015",
                "a non-empty hot pass must identify at least one accessed field",
            );
            continue;
        }

        let Some(record_bytes) = region
            .field_bytes
            .iter()
            .try_fold(0_u64, |total, bytes| total.checked_add(u64::from(*bytes)))
        else {
            push_error(
                &mut report.errors,
                Some(&region.name),
                "ORES-LAYOUT016",
                "record byte width overflow",
            );
            continue;
        };

        let fraction = ((u128::from(accessed_bytes) * 1000) / u128::from(record_bytes)) as u16;
        let blockers = relocation_blockers(region);
        let rows_large = region.rows.is_some_and(|rows| rows >= 128);
        let field_selective = !region.accessed_fields.is_empty() && fraction <= 500;
        let moderately_wide = (501..=850).contains(&fraction);
        let traversal_friendly = region.dense_iteration && region.sequential_rows;

        let max_accessed_width = region
            .accessed_fields
            .iter()
            .filter_map(|index| region.field_bytes.get(*index as usize))
            .copied()
            .max();
        let suggested_tile_rows = match (program.target.vector_bytes, max_accessed_width) {
            (Some(vector), Some(field)) if vector >= field.saturating_mul(2) => {
                Some((vector / field).clamp(2, 64))
            }
            _ => None,
        };

        report.regions.insert(
            region.name.clone(),
            RegionSummary {
                scope: region.scope,
                current_layout: region.layout,
                rows: region.rows,
                record_bytes,
                accessed_field_bytes: accessed_bytes,
                accessed_fraction_permille: fraction,
                suggested_aosoa_tile_rows: suggested_tile_rows,
                transform_suppressed_by: blockers.clone(),
            },
        );

        let soa_candidate = region.hot
            && rows_large
            && region.field_bytes.len() >= 4
            && field_selective
            && traversal_friendly
            && matches!(region.layout, Layout::Aos);

        if soa_candidate {
            if blockers.is_empty() {
                add_finding(
                    &mut report.findings,
                    region,
                    "ORES-LAYOUT101",
                    "soa_candidate",
                    "medium",
                    format!(
                        "AoS hot pass touches {accessed_bytes}/{record_bytes} declared field bytes per row; benchmark SoA against the current layout."
                    ),
                );
            } else if blockers.len() == 1 && blockers[0] == "relocation_not_verified" {
                add_finding(
                    &mut report.findings,
                    region,
                    "ORES-LAYOUT102",
                    "soa_candidate_blocked",
                    "medium",
                    "Field-selective dense traversal is a SoA candidate, but relocation/ownership safety has not been verified.",
                );
            } else {
                add_finding(
                    &mut report.findings,
                    region,
                    "ORES-LAYOUT103",
                    "layout_transform_suppressed",
                    "high",
                    format!(
                        "Potential SoA rewrite intentionally suppressed by semantic/access constraints: {}.",
                        blockers.join(", ")
                    ),
                );
            }
        }

        let aosoa_candidate = region.hot
            && rows_large
            && region.accessed_fields.len() >= 2
            && moderately_wide
            && traversal_friendly
            && region.iteration_independent
            && suggested_tile_rows.is_some()
            && matches!(region.layout, Layout::Aos | Layout::Soa);

        if aosoa_candidate && blockers.is_empty() {
            add_finding(
                &mut report.findings,
                region,
                "ORES-LAYOUT111",
                "aosoa_candidate",
                "medium",
                format!(
                    "Independent sequential pass with target vector width {:?} bytes suggests benchmarking AoSoA with an initial tile of {} rows.",
                    program.target.vector_bytes,
                    suggested_tile_rows.unwrap_or(2)
                ),
            );
        }

        let ecs_candidate = region.hot
            && rows_large
            && region.sparse_membership
            && region.independent_component_passes
            && region.accessed_fields.len() < region.field_bytes.len()
            && !matches!(region.layout, Layout::SparseSet | Layout::Archetype);

        if ecs_candidate {
            if blockers.is_empty() {
                add_finding(
                    &mut report.findings,
                    region,
                    "ORES-LAYOUT121",
                    "ecs_candidate",
                    "medium",
                    "Sparse membership plus independently selected component passes suggests benchmarking sparse-set or archetype/ECS storage.",
                );
            } else {
                add_finding(
                    &mut report.findings,
                    region,
                    "ORES-LAYOUT122",
                    "ecs_candidate_blocked",
                    "high",
                    format!(
                        "ECS-style storage candidate is not safe to propose automatically because: {}.",
                        blockers.join(", ")
                    ),
                );
            }
        }

        if region.hot && region.rows != Some(0) && region.concurrent_mutable_sharing {
            add_finding(
                &mut report.findings,
                region,
                "ORES-LAYOUT201",
                "false_sharing_risk",
                "low",
                "Concurrent mutable sharing can create cache-line contention; confirm with target-specific profiling before padding or separating fields.",
            );
        }

        if region.hot && rows_large && !region.sequential_rows {
            add_finding(
                &mut report.findings,
                region,
                "ORES-LAYOUT301",
                "locality_risk",
                "low",
                "Non-sequential hot access warrants locality/pointer-chasing profiling before choosing compaction, sparse sets, archetypes, or reordering.",
            );
        }
    }

    report.findings.sort_by(|a, b| {
        (a.region.as_str(), a.code, a.kind).cmp(&(b.region.as_str(), b.code, b.kind))
    });
    report.errors.sort_by(|a, b| {
        (a.region.as_deref(), a.code, a.message.as_str())
            .cmp(&(b.region.as_deref(), b.code, b.message.as_str()))
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            cache_line_bytes: Some(64),
            vector_bytes: Some(32),
        }
    }

    fn base_region() -> Region {
        Region {
            name: "physics.positions".into(),
            scope: Scope::Userland,
            layout: Layout::Aos,
            rows: Some(10_000),
            field_bytes: vec![4, 4, 4, 4, 8, 8, 8, 8],
            accessed_fields: vec![0, 1],
            dense_iteration: true,
            sequential_rows: true,
            hot: true,
            relocation_verified: true,
            stable_address_required: false,
            whole_record_access: false,
            iteration_independent: true,
            sparse_membership: false,
            independent_component_passes: false,
            concurrent_mutable_sharing: false,
        }
    }

    fn program(region: Region) -> LayoutProgram {
        LayoutProgram {
            schema_version: LAYOUT_SCHEMA_VERSION,
            evidence_complete: true,
            target: target(),
            regions: vec![region],
        }
    }

    fn codes(report: &LayoutReport) -> Vec<&'static str> {
        report.findings.iter().map(|finding| finding.code).collect()
    }

    #[test]
    fn detects_field_selective_dense_aos_as_soa_candidate() {
        let report = analyze_layout(&program(base_region()));
        assert!(codes(&report).contains(&"ORES-LAYOUT101"));
        assert!(!report.has_errors());
    }

    #[test]
    fn detects_vector_friendly_middle_width_pass_as_aosoa_candidate() {
        let mut region = base_region();
        region.accessed_fields = vec![0, 1, 2, 3, 4, 5];
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT111"));
        assert!(!codes(&report).contains(&"ORES-LAYOUT101"));
    }

    #[test]
    fn detects_sparse_independent_components_as_ecs_candidate() {
        let mut region = base_region();
        region.sparse_membership = true;
        region.independent_component_passes = true;
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT121"));
    }

    #[test]
    fn whole_record_or_stable_address_suppresses_layout_rewrite() {
        let mut region = base_region();
        region.whole_record_access = true;
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT103"));
        assert!(!codes(&report).contains(&"ORES-LAYOUT101"));

        let mut region = base_region();
        region.stable_address_required = true;
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT103"));
    }

    #[test]
    fn unverified_relocation_is_not_presented_as_safe_rewrite() {
        let mut region = base_region();
        region.relocation_verified = false;
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT102"));
        assert!(!codes(&report).contains(&"ORES-LAYOUT101"));
    }

    #[test]
    fn cold_or_small_regions_do_not_get_layout_recommendations() {
        let mut region = base_region();
        region.hot = false;
        assert!(analyze_layout(&program(region)).findings.is_empty());

        let mut region = base_region();
        region.rows = Some(16);
        assert!(analyze_layout(&program(region)).findings.is_empty());
    }

    #[test]
    fn incomplete_evidence_fails_closed_and_suppresses_findings() {
        let mut p = program(base_region());
        p.evidence_complete = false;
        let report = analyze_layout(&p);
        assert!(report.has_errors());
        assert!(report.findings.is_empty());
        assert_eq!(report.errors[0].code, "ORES-LAYOUT002");
    }

    #[test]
    fn duplicate_or_out_of_range_access_indexes_are_rejected() {
        let mut region = base_region();
        region.accessed_fields = vec![0, 0];
        assert_eq!(
            analyze_layout(&program(region)).errors[0].code,
            "ORES-LAYOUT013"
        );

        let mut region = base_region();
        region.accessed_fields = vec![99];
        assert_eq!(
            analyze_layout(&program(region)).errors[0].code,
            "ORES-LAYOUT014"
        );
    }

    #[test]
    fn duplicate_region_names_are_rejected() {
        let region = base_region();
        let p = LayoutProgram {
            schema_version: 1,
            evidence_complete: true,
            target: target(),
            regions: vec![region.clone(), region],
        };
        assert!(analyze_layout(&p)
            .errors
            .iter()
            .any(|error| error.code == "ORES-LAYOUT011"));
    }

    #[test]
    fn invalid_target_width_fails_closed() {
        let mut p = program(base_region());
        p.target.vector_bytes = Some(24);
        let report = analyze_layout(&p);
        assert_eq!(report.errors[0].code, "ORES-LAYOUT003");
        assert!(report.findings.is_empty());
    }

    #[test]
    fn excessive_structural_evidence_fails_closed() {
        let mut region = base_region();
        region.field_bytes = vec![4; MAX_FIELDS_PER_REGION + 1];
        region.accessed_fields = vec![0];
        let report = analyze_layout(&program(region));
        assert_eq!(report.errors[0].code, "ORES-LAYOUT007");
        assert!(report.findings.is_empty());

        let mut region = base_region();
        region.name = "x".repeat(MAX_REGION_NAME_BYTES + 1);
        let report = analyze_layout(&program(region));
        assert_eq!(report.errors[0].code, "ORES-LAYOUT006");
        assert!(report.errors[0].region.is_none());
    }

    #[test]
    fn flags_possible_false_sharing_without_claiming_proof() {
        let mut region = base_region();
        region.concurrent_mutable_sharing = true;
        assert!(codes(&analyze_layout(&program(region))).contains(&"ORES-LAYOUT201"));
    }

    #[test]
    fn zero_row_region_does_not_report_false_sharing() {
        let mut region = base_region();
        region.rows = Some(0);
        region.accessed_fields.clear();
        region.concurrent_mutable_sharing = true;
        assert!(analyze_layout(&program(region)).findings.is_empty());
    }

    #[test]
    fn non_sequential_hot_access_gets_locality_advice_not_soa() {
        let mut region = base_region();
        region.sequential_rows = false;
        let report = analyze_layout(&program(region));
        assert!(codes(&report).contains(&"ORES-LAYOUT301"));
        assert!(!codes(&report).contains(&"ORES-LAYOUT101"));
    }

    #[test]
    fn unknown_fields_in_json_are_rejected_by_schema() {
        let json = r#"{"schema_version":1,"evidence_complete":true,"target":{"cache_line_bytes":64,"vector_bytes":32},"regions":[{"name":"x","scope":"core","layout":"aos","rows":128,"field_bytes":[4],"accessed_fields":[0],"dense_iteration":true,"sequential_rows":true,"hot":true,"relocation_verified":true,"stable_address_required":false,"whole_record_access":false,"iteration_independent":true,"sparse_membership":false,"independent_component_passes":false,"concurrent_mutable_sharing":false,"surprise":1}]}"#;
        assert!(serde_json::from_str::<LayoutProgram>(json).is_err());
    }
}
