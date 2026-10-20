//! Conservative, memoized interprocedural summaries for a *pure scalar* MIR subset.
//! No arbitrary effects are inferred safe. Calls are admitted only when every
//! transitive callee has an independently checked straight-line scalar body.
use crate::flow::{Domain, FlowFunction, FlowOp, Terminator};
use std::collections::{HashMap, HashSet};

const MAX_CALL_DEPTH: usize = 64;
pub(crate) type PureSummaries = HashMap<String, Result<u64, String>>;

fn summary<'a>(
    name: &str,
    index: &HashMap<&'a str, &'a FlowFunction>,
    cache: &mut PureSummaries,
    active: &mut HashSet<String>,
    depth: usize,
) -> Result<u64, String> {
    if let Some(saved) = cache.get(name) {
        return saved.clone();
    }
    if depth >= MAX_CALL_DEPTH {
        return Err(format!("call chain exceeds {MAX_CALL_DEPTH} frames: {name}"));
    }
    if !active.insert(name.to_owned()) {
        return Err(format!("recursive call cycle involving '{name}' has no verified bound"));
    }
    let outcome = (|| {
        let func = index
            .get(name)
            .ok_or_else(|| format!("unresolved call target '{name}'"))?;
        // Version one only admits a pure, single-block, straight-line callee.
        // It deliberately rejects suspends, cooperating checkpoints, actor
        // transfers, borrows, returns with live loans and other effects.
        if func.blocks.len() != 1
            || func.blocks[0].id != func.entry
            || !matches!(func.blocks[0].terminator, Terminator::Return)
        {
            return Err(format!("callee '{name}' requires a verified CFG summary"));
        }
        let mut work = 0_u64;
        let mut locals = HashSet::new();
        for op in &func.blocks[0].ops {
            match op {
                FlowOp::Compute { units: Some(units) } => {
                    work = work.checked_add(*units)
                        .ok_or_else(|| format!("abstract work overflow in '{name}'"))?;
                }
                FlowOp::Declare { place, domain: Domain::Local } => {
                    if place.trim().is_empty() || !locals.insert(place.as_str()) {
                        return Err(format!("invalid local declaration in '{name}': {place}"));
                    }
                }
                FlowOp::Read { place } => {
                    if !locals.contains(place.as_str()) {
                        return Err(format!("unresolved local read in '{name}': {place}"));
                    }
                }
                FlowOp::Call { target } => {
                    let callee = summary(target, index, cache, active, depth + 1)?;
                    work = work.checked_add(callee)
                        .and_then(|x| x.checked_add(1)) // call-site abstract dispatch
                        .ok_or_else(|| format!("abstract call work overflow in '{name}'"))?;
                }
                _ => {
                    return Err(format!(
                        "callee '{name}' contains non-scalar, unbounded or stateful effects"
                    ));
                }
            }
        }
        Ok(work)
    })();
    active.remove(name);
    cache.insert(name.to_owned(), outcome.clone());
    outcome
}

/// Validate only functions actually invoked by an IR Call event. A conservative
/// negative result is cached too. The enclosing CFG still checks *all* functions.
pub(crate) fn compute_pure_summaries(functions: &[FlowFunction]) -> PureSummaries {
    let mut index = HashMap::new();
    let mut duplicate_names = HashSet::new();
    for function in functions {
        if index.insert(function.name.as_str(), function).is_some() {
            duplicate_names.insert(function.name.clone());
        }
    }
    let mut calls = Vec::new();
    for function in functions {
        for block in &function.blocks {
            for op in &block.ops {
                if let FlowOp::Call { target } = op {
                    calls.push(target.as_str());
                }
            }
        }
    }
    let mut cache = PureSummaries::new();
    let mut active = HashSet::new();
    for name in calls {
        if duplicate_names.contains(name) {
            cache.insert(name.to_owned(), Err(format!("ambiguous callee: {name}")));
            continue;
        }
        let _ = summary(name, &index, &mut cache, &mut active, 0);
    }
    cache
}

#[cfg(test)]
mod tests {
    use super::*;
    fn program(json: &str) -> Vec<FlowFunction> {
        serde_json::from_str::<crate::flow::FlowProgram>(json).unwrap().functions
    }
    #[test]
    fn admits_bounded_scalar_forward_call() {
        let functions = program(r#"{"schema_version":1,"effects_complete":true,"functions":[
          {"name":"caller","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"call","target":"calc"}],"terminator":{"kind":"return"}}]},
          {"name":"calc","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"compute","units":3}],"terminator":{"kind":"return"}}]}
        ]}"#);
        assert_eq!(compute_pure_summaries(&functions)["calc"], Ok(3));
    }
    #[test]
    fn rejects_recursive_calls() {
        let functions = program(r#"{"schema_version":1,"effects_complete":true,"functions":[
          {"name":"a","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"call","target":"b"}],"terminator":{"kind":"return"}}]},
          {"name":"b","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"call","target":"a"}],"terminator":{"kind":"return"}}]}
        ]}"#);
        assert!(compute_pure_summaries(&functions)["a"].is_err());
    }
    #[test]
    fn rejects_impure_transfer_even_if_labelled_immutable() {
        let functions = program(r#"{"schema_version":1,"effects_complete":true,"functions":[
          {"name":"call","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"call","target":"unsafe"}],"terminator":{"kind":"return"}}]},
          {"name":"unsafe","entry":"b","max_uninterrupted_units":10,
           "blocks":[{"id":"b","ops":[{"kind":"declare","place":"x","domain":"shared_immutable"}],"terminator":{"kind":"return"}}]}
        ]}"#);
        assert!(compute_pure_summaries(&functions)["unsafe"].is_err());
    }
}
