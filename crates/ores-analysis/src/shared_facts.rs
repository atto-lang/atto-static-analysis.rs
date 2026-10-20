//! Restricted importer for ores-static-facts/v0. Deliberately *advisory* only.
//!
//! This is not an authenticated compiler proof. Empty taint/sink arrays and
//! unknown loop bounds are not evidence of whole-program runtime safety.
//! The adapter accepts only the Java scalar closed-world subset and refuses
//! every construct whose effects the v1 Rust engine cannot represent.
use crate::{Function, Operation, Program, SCHEMA_VERSION};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedFactsV0 {
    pub version: String,
    pub unit: String,
    pub procedures: Vec<FactProcedure>,
    pub edges: Vec<FactEdge>,
    pub taint_sources: Vec<serde::de::IgnoredAny>,
    pub flows: Vec<serde::de::IgnoredAny>,
    pub sinks: Vec<serde::de::IgnoredAny>,
    pub permission_checks: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    pub callback_orderings: Vec<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactProcedure {
    pub id: String,
    pub loops: Vec<FactLoop>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactLoop {
    pub id: String,
    pub exit: String,
    pub safepoint: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactEdge {
    #[serde(rename = "from")]
    pub source: String,
    pub to: String,
    pub kind: String,
    pub fanout: u64,
    pub guard: String,
}

fn identifier(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
}

impl SharedFactsV0 {
    /// Convert only permitted scalar facts. Never emit strict admission proofs.
    pub fn advisory_effect_ir(&self) -> Result<Program, String> {
        if self.version != "ores-static-facts/v0" {
            return Err("unsupported shared static facts schema version".into());
        }
        if self.unit.len() != 71
            || !self.unit.starts_with("sha256:")
            || !self.unit[7..].bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err("unverified or malformed source identity; expected sha256:<64 lowercase hex>".into());
        }
        // Bound importer graph size below the recursive reference engine's
        // stack-sensitive call traversal until iterative SCC lowering exists.
        if self.procedures.is_empty() || self.procedures.len() > 512 || self.edges.len() > 8_192 {
            return Err("invalid static facts collection size".into());
        }
        if !self.taint_sources.is_empty() || !self.flows.is_empty() || !self.sinks.is_empty()
            || !self.permission_checks.is_empty() || !self.callback_orderings.is_empty()
        {
            return Err("security/callback facts are not admitted by scalar importer".into());
        }
        let mut index = HashMap::new();
        let mut functions = Vec::with_capacity(self.procedures.len());
        let mut total_loops = 0usize;
        for fact in &self.procedures {
            if !identifier(&fact.id) || index.insert(fact.id.as_str(), functions.len()).is_some() {
                return Err("invalid or duplicated procedure identity".into());
            }
            total_loops = total_loops.saturating_add(fact.loops.len());
            if fact.loops.len() > 256 || total_loops > 4_096 {
                return Err("static-facts loop work exceeds conservative analysis budget".into());
            }
            let mut loops = HashSet::new();
            for l in &fact.loops {
                if !identifier(&l.id) || !loops.insert(l.id.as_str()) {
                    return Err("invalid or duplicated loop identity".into());
                }
                // The prototype AST exporter has neither ranking-function
                // proofs nor authenticated scheduler-safepoint evidence.
                if l.exit != "unknown" || l.safepoint {
                    return Err("asserted loop termination/safepoint proof unsupported".into());
                }
            }
            let mut operations = Vec::new();
            // Explicitly discard *all* numeric allocation/copy/work bounds.
            // Java boxed execution and backend lowering are not certified
            // by this representation. Never replace unknown with zero.
            operations.push(Operation::Allocate { bytes: None });
            operations.push(Operation::Copy { bytes: None });
            operations.push(Operation::Compute { units: None });
            for _ in &fact.loops {
                operations.push(Operation::Loop {
                    iterations: None,
                    operations: vec![Operation::Compute { units: None }],
                });
            }
            functions.push(Function { name: fact.id.clone(), operations });
        }
        let mut seen_edges = HashSet::new();
        for e in &self.edges {
            if !seen_edges.insert((e.source.as_str(), e.to.as_str())) {
                return Err("duplicate call edge is not a proof of repeated-call fanout".into());
            }
            if e.kind != "call" || e.fanout != 1 || e.guard != "unproved" {
                return Err("non-scalar edge or forged cycle bound rejected".into());
            }
            let Some(&source_index) = index.get(e.source.as_str()) else {
                return Err("unresolved call source".into());
            };
            if !index.contains_key(e.to.as_str()) {
                return Err("unresolved callee (cannot certify direct dispatch)".into());
            }
            functions[source_index].operations.push(Operation::Call { target: e.to.clone() });
        }
        Ok(Program { schema_version: SCHEMA_VERSION, functions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GOOD: &str = r#"{
        "version":"ores-static-facts/v0",
        "unit":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "procedures":[
          {"id":"__root__.again/1","loops":[]},
          {"id":"__root__.main/0","loops":[]}],
        "edges":[
          {"from":"__root__.again/1","to":"__root__.again/1","kind":"call","fanout":1,"guard":"unproved"},
          {"from":"__root__.main/0","to":"__root__.again/1","kind":"call","fanout":1,"guard":"unproved"}
        ],
        "taint_sources":[],"flows":[],"sinks":[],"permission_checks":[]
    }"#;

    #[test]
    fn recursion_visible_to_existing_engine_without_zero_work_certificate() {
        let facts: SharedFactsV0 = serde_json::from_str(GOOD).unwrap();
        let ir = facts.advisory_effect_ir().unwrap();
        let report = crate::analyze(&ir, crate::Profile::General);
        assert!(report.diagnostics.iter().any(|d| d.code == "ORES-SA102"));
        assert_eq!(report.functions["__root__.main/0"].operations_upper_bound, None);
        assert_eq!(report.functions["__root__.main/0"].allocations_upper_bound, None);
    }

    #[test]
    fn loop_never_becomes_proved_finite() {
        let source = GOOD.replace("\"loops\":[]", "\"loops\":[{\"id\":\"L1\",\"exit\":\"unknown\",\"safepoint\":false}]");
        let facts: SharedFactsV0 = serde_json::from_str(&source).unwrap();
        let report = crate::analyze(&facts.advisory_effect_ir().unwrap(), crate::Profile::General);
        assert!(report.diagnostics.iter().any(|d| d.code == "ORES-SA104"));
    }

    #[test]
    fn caller_can_never_assert_proof_or_unknown_effect_as_scalar() {
        for text in [
            GOOD.replace("\"guard\":\"unproved\"", "\"guard\":\"proved_bounded\""),
            GOOD.replace("\"kind\":\"call\"", "\"kind\":\"actor_spawn\""),
            GOOD.replace("\"taint_sources\":[]", "\"taint_sources\":[{\"id\":\"secret\",\"class\":\"secret\"}]"),
            GOOD.replace("\"loops\":[]", "\"loops\":[{\"id\":\"L1\",\"exit\":\"proved_terminates\",\"safepoint\":false}]"),
            GOOD.replace("\"version\":\"ores-static-facts/v0\"", "\"version\":\"untrusted\""),
        ] {
            match serde_json::from_str::<SharedFactsV0>(&text) {
                Ok(doc) => assert!(doc.advisory_effect_ir().is_err()),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn schema_extra_fields_rejected() {
        let text = GOOD.replace("\"unit\":", "\"producer_claim\":\"trusted\",\"unit\":");
        assert!(serde_json::from_str::<SharedFactsV0>(&text).is_err());
    }

    #[test]
    fn duplicated_call_edges_fail_closed_instead_of_disappearing() {
        let source = GOOD.replace(
            "\"edges\":[",
            "\"edges\":[{\"from\":\"__root__.main/0\",\"to\":\"__root__.again/1\",\"kind\":\"call\",\"fanout\":1,\"guard\":\"unproved\"},"
        );
        let facts: SharedFactsV0 = serde_json::from_str(&source).unwrap();
        assert!(facts.advisory_effect_ir().is_err());
    }

    #[test]
    fn oversized_loop_facts_are_rejected_before_ir_allocation() {
        let mut doc: serde_json::Value = serde_json::from_str(GOOD).unwrap();
        doc["procedures"][0]["loops"] = serde_json::Value::Array(
            (0..257).map(|i| serde_json::json!({
                "id": format!("L{i}"), "exit":"unknown", "safepoint":false
            })).collect()
        );
        let facts: SharedFactsV0 = serde_json::from_value(doc).unwrap();
        assert!(facts.advisory_effect_ir().is_err());
    }

    #[test]
    fn source_hash_field_is_not_assumed_to_be_attestation() {
        let text = GOOD.replace("sha256:", "sha384:");
        let facts: SharedFactsV0 = serde_json::from_str(&text).unwrap();
        assert!(facts.advisory_effect_ir().is_err());
    }
}
