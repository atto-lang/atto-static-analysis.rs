//! Conservative safety admission for complete, *straight-line* MIR event traces.
//! This is not a full CFG borrow checker or a global deadlock/WCET proof.
//! Unknown calls, paths and lock identities are rejected, never assumed safe.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyProgram {
    pub schema_version: u32,
    /// Caller attests that the IR enumerates all relevant effects. Input alone
    /// cannot independently verify this claim; the compiler must prove it.
    pub effects_complete: bool,
    pub functions: Vec<SafetyFunction>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyFunction {
    pub name: String,
    /// Only a validated straight-line CFG is admissible in this prototype.
    pub control_flow: String,
    /// Maximum allowed abstract compute units without a cooperative checkpoint.
    pub max_uninterrupted_units: Option<u64>,
    pub allow_error_propagation: bool,
    pub events: Vec<Event>,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Define {
        place: String,
    },
    Read {
        place: String,
    },
    Write {
        place: String,
    },
    Move {
        place: String,
    },
    Borrow {
        place: String,
        loan: String,
        mutable: bool,
    },
    EndBorrow {
        loan: String,
    },
    ActorTransfer {
        place: String,
        mutable: bool,
    },
    Lock {
        id: String,
    },
    Unlock {
        id: String,
    },
    Compute {
        units: Option<u64>,
    },
    Cooperate,
    Suspend,
    Wait {
        bounded: bool,
    },
    Allocate {
        bytes: Option<u64>,
    },
    UnsafeFfi,
    /// Calls without a validated interprocedural summary are a proof gap.
    Call {
        target: String,
    },
    /// A named, fallible effect must be handled or explicitly propagated.
    MayFail {
        error: String,
    },
    Catch {
        error: String,
    },
    Propagate {
        error: String,
    },
    Panic,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SafetyProfile {
    General,
    Soft,
    Hard,
}
#[derive(Debug, Serialize)]
pub struct SafetyDiagnostic {
    pub code: &'static str,
    pub function: String,
    pub event_index: Option<usize>,
    pub message: String,
    pub severity: &'static str,
}
#[derive(Debug, Serialize)]
pub struct SafetyReport {
    pub schema_version: u32,
    pub assurance_scope: &'static str,
    /// This refers to modeled static admission only, never hard-RT certification.
    pub admitted_to_static_gate: bool,
    pub hard_realtime_certified: bool,
    pub diagnostics: Vec<SafetyDiagnostic>,
    pub lock_order_edges: BTreeMap<String, Vec<String>>,
}
#[derive(Default)]
struct State {
    values: HashMap<String, bool>, // true means still owned, false means moved
    loans: HashMap<String, (String, bool)>,
    held_locks: Vec<String>,
    failures: HashSet<String>,
    compute_since_checkpoint: Option<u64>,
}
fn report(
    diags: &mut Vec<SafetyDiagnostic>,
    code: &'static str,
    name: &str,
    index: Option<usize>,
    severity: &'static str,
    message: impl Into<String>,
) {
    diags.push(SafetyDiagnostic {
        code,
        function: name.to_owned(),
        event_index: index,
        severity,
        message: message.into(),
    });
}
fn active_loans(state: &State, place: &str) -> (usize, usize) {
    state
        .loans
        .values()
        .fold((0, 0), |(shared, mutable), (p, m)| {
            if p == place {
                if *m {
                    (shared, mutable + 1)
                } else {
                    (shared + 1, mutable)
                }
            } else {
                (shared, mutable)
            }
        })
}
fn check_owned(state: &State, place: &str) -> bool {
    state.values.get(place) == Some(&true)
}
fn cycle(edges: &BTreeMap<String, BTreeSet<String>>) -> Option<Vec<String>> {
    fn visit(
        node: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        marks: &mut HashMap<String, u8>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        match marks.get(node).copied() {
            Some(1) => {
                let at = stack.iter().position(|x| x == node).unwrap_or(0);
                let mut chain = stack[at..].to_vec();
                chain.push(node.to_owned());
                return Some(chain);
            }
            Some(2) => return None,
            _ => {}
        }
        marks.insert(node.to_owned(), 1);
        stack.push(node.to_owned());
        if let Some(next) = edges.get(node) {
            for target in next {
                if let Some(result) = visit(target, edges, marks, stack) {
                    return Some(result);
                }
            }
        }
        stack.pop();
        marks.insert(node.to_owned(), 2);
        None
    }
    let mut marks = HashMap::new();
    for node in edges.keys() {
        if let Some(result) = visit(node, edges, &mut marks, &mut Vec::new()) {
            return Some(result);
        }
    }
    None
}
pub fn analyze_safety(program: &SafetyProgram, profile: SafetyProfile) -> SafetyReport {
    let mut diagnostics = Vec::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if program.schema_version != 1 || !program.effects_complete {
        report(
            &mut diagnostics,
            "ORES-SAF001",
            "<module>",
            None,
            "error",
            "unsupported schema or effect manifest is not marked complete",
        );
    }
    let mut function_names = HashSet::new();
    for function in &program.functions {
        if function.name.trim().is_empty() || !function_names.insert(&function.name) {
            report(
                &mut diagnostics,
                "ORES-SAF002",
                &function.name,
                None,
                "error",
                "duplicate or blank function name",
            );
        }
        if function.control_flow != "linear" {
            report(
                &mut diagnostics,
                "ORES-SAF003",
                &function.name,
                None,
                "error",
                "control flow requires CFG-sensitive analysis; only checked linear IR is accepted",
            );
            continue;
        }
        let mut state = State {
            compute_since_checkpoint: Some(0),
            ..State::default()
        };
        for (i, event) in function.events.iter().enumerate() {
            let err = |diags: &mut Vec<SafetyDiagnostic>, code, reason: String| {
                report(diags, code, &function.name, Some(i), "error", reason)
            };
            match event {
                Event::Define { place } => {
                    if place.is_empty() || state.values.contains_key(place) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF100",
                            format!("invalid or redeclared owned place '{place}'"),
                        );
                    } else {
                        state.values.insert(place.clone(), true);
                    }
                }
                Event::Read { place } => {
                    if !check_owned(&state, place) || active_loans(&state, place).1 > 0 {
                        err(
                            &mut diagnostics,
                            "ORES-SAF101",
                            format!("read of unavailable or mutably loaned place '{place}'"),
                        );
                    }
                }
                Event::Write { place } => {
                    if !check_owned(&state, place) || active_loans(&state, place) != (0, 0) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF102",
                            format!("write while moved or borrowed: '{place}'"),
                        );
                    }
                }
                Event::Move { place } => {
                    if !check_owned(&state, place) || active_loans(&state, place) != (0, 0) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF103",
                            format!("move while unavailable or borrowed: '{place}'"),
                        );
                    } else {
                        state.values.insert(place.clone(), false);
                    }
                }
                Event::Borrow {
                    place,
                    loan,
                    mutable,
                } => {
                    let (shared, exclusive) = active_loans(&state, place);
                    if loan.is_empty()
                        || state.loans.contains_key(loan)
                        || !check_owned(&state, place)
                        || (if *mutable {
                            shared > 0 || exclusive > 0
                        } else {
                            exclusive > 0
                        })
                    {
                        err(
                            &mut diagnostics,
                            "ORES-SAF104",
                            format!("conflicting or invalid loan '{loan}' on '{place}'"),
                        );
                    } else {
                        state.loans.insert(loan.clone(), (place.clone(), *mutable));
                    }
                }
                Event::EndBorrow { loan } => {
                    if state.loans.remove(loan).is_none() {
                        err(
                            &mut diagnostics,
                            "ORES-SAF105",
                            format!("ending unknown or already ended loan '{loan}'"),
                        );
                    }
                }
                Event::ActorTransfer { place, mutable } => {
                    if !check_owned(&state, place)
                        || *mutable
                        || active_loans(&state, place) != (0, 0)
                    {
                        err(&mut diagnostics, "ORES-SAF106", format!("actor boundary transfer requires a valid, independently proven immutable share: '{place}'"));
                    } else {
                        // An immutable transfer is *not* automatically safe: the domain
                        // and freeze proofs are unavailable in v1.
                        err(
                            &mut diagnostics,
                            "ORES-SAF107",
                            format!("share domain/freeze proof missing for '{place}'"),
                        );
                    }
                }
                Event::Lock { id } => {
                    if id.trim().is_empty() || state.held_locks.contains(id) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF200",
                            format!("invalid/reentrant lock acquisition '{id}'"),
                        );
                    } else {
                        for prior in &state.held_locks {
                            edges.entry(prior.clone()).or_default().insert(id.clone());
                        }
                        state.held_locks.push(id.clone());
                    }
                }
                Event::Unlock { id } => {
                    if state.held_locks.last() != Some(id) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF201",
                            format!("unbalanced or non-LIFO lock release '{id}'"),
                        );
                    } else {
                        state.held_locks.pop();
                    }
                }
                Event::Compute { units } => {
                    state.compute_since_checkpoint = state
                        .compute_since_checkpoint
                        .and_then(|x| x.checked_add(units.as_ref().copied()?));
                    if state.compute_since_checkpoint.is_none() {
                        err(
                            &mut diagnostics,
                            "ORES-SAF300",
                            "compute bound unknown or overflowed".into(),
                        );
                    }
                    if profile != SafetyProfile::General {
                        if let (Some(actual), Some(max)) = (
                            state.compute_since_checkpoint,
                            function.max_uninterrupted_units,
                        ) {
                            if actual > max {
                                err(&mut diagnostics, "ORES-SAF301", format!("cooperation bound exceeded: {actual} > {max} abstract units"));
                            }
                        }
                    }
                }
                Event::Cooperate => {
                    state.compute_since_checkpoint = Some(0);
                }
                Event::Suspend => {
                    if !state.loans.is_empty() || !state.held_locks.is_empty() {
                        err(&mut diagnostics, "ORES-SAF302", "suspension with live loans or acquired locks; pinned/actor state exceptions unproven".into());
                    }
                    state.compute_since_checkpoint = Some(0);
                }
                Event::Wait { bounded } => {
                    if !*bounded || !state.held_locks.is_empty() {
                        err(
                            &mut diagnostics,
                            "ORES-SAF202",
                            "unbounded wait or wait while holding lock".into(),
                        );
                    }
                }
                Event::Allocate { bytes } => {
                    if profile == SafetyProfile::Hard && *bytes != Some(0) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF400",
                            "hard-RT allocation-free requirement not established".into(),
                        );
                    } else if profile == SafetyProfile::Soft && bytes.is_none() {
                        err(
                            &mut diagnostics,
                            "ORES-SAF401",
                            "soft-RT allocation bound is unknown".into(),
                        );
                    }
                }
                Event::UnsafeFfi => {
                    if profile != SafetyProfile::General {
                        err(
                            &mut diagnostics,
                            "ORES-SAF402",
                            "FFI has no independently checked timing/ownership contract".into(),
                        );
                    }
                }
                Event::Call { target } => {
                    err(&mut diagnostics, "ORES-SAF500", format!("call to '{target}' lacks compositional ownership/lock/cooperation summary"));
                }
                Event::MayFail { error } => {
                    if error.is_empty() || !state.failures.insert(error.clone()) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF600",
                            format!("invalid/reused error effect id '{error}'"),
                        );
                    }
                }
                Event::Catch { error } => {
                    if !state.failures.remove(error) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF601",
                            format!("catch without pending error effect '{error}'"),
                        );
                    }
                }
                Event::Propagate { error } => {
                    if !function.allow_error_propagation || !state.failures.remove(error) {
                        err(
                            &mut diagnostics,
                            "ORES-SAF602",
                            format!("unapproved error propagation '{error}'"),
                        );
                    }
                }
                Event::Panic => {
                    err(
                        &mut diagnostics,
                        "ORES-SAF603",
                        "panic requires an explicitly modeled supervisor/fatal boundary".into(),
                    );
                }
            }
        }
        if !state.loans.is_empty() {
            report(
                &mut diagnostics,
                "ORES-SAF108",
                &function.name,
                None,
                "error",
                "live loans at function exit",
            );
        }
        if !state.held_locks.is_empty() {
            report(
                &mut diagnostics,
                "ORES-SAF203",
                &function.name,
                None,
                "error",
                "locks held at function exit",
            );
        }
        if !state.failures.is_empty() {
            report(
                &mut diagnostics,
                "ORES-SAF604",
                &function.name,
                None,
                "error",
                "unhandled fallible effects",
            );
        }
        if profile != SafetyProfile::General && function.max_uninterrupted_units.is_none() {
            report(
                &mut diagnostics,
                "ORES-SAF303",
                &function.name,
                None,
                "error",
                "cooperation budget not provided",
            );
        }
    }
    if let Some(chain) = cycle(&edges) {
        report(
            &mut diagnostics,
            "ORES-SAF204",
            "<module>",
            None,
            "error",
            format!("potential lock-order cycle: {}", chain.join(" -> ")),
        );
    }
    diagnostics.sort_by(|a, b| {
        (a.function.as_str(), a.event_index, a.code).cmp(&(
            b.function.as_str(),
            b.event_index,
            b.code,
        ))
    });
    SafetyReport {
        schema_version: 1,
        assurance_scope:
            "checked_linear_effect_ir_only; no CFG, WCET, scheduler, runtime or dynamic wait proof",
        admitted_to_static_gate: diagnostics.iter().all(|d| d.severity != "error"),
        hard_realtime_certified: false,
        diagnostics,
        lock_order_edges: edges
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn case(events: &str, budget: Option<u64>) -> SafetyProgram {
        let budget_str = budget.map_or("null".to_owned(), |v| v.to_string());
        serde_json::from_str(&format!(r#"{{"schema_version":1,"effects_complete":true,"functions":[{{"name":"work","control_flow":"linear","max_uninterrupted_units":{budget_str},"allow_error_propagation":false,"events":{events}}}]}}"#)).unwrap()
    }
    fn codes(program: &SafetyProgram, profile: SafetyProfile) -> Vec<&'static str> {
        analyze_safety(program, profile)
            .diagnostics
            .iter()
            .map(|d| d.code)
            .collect()
    }
    #[test]
    fn valid_loan_and_cooperation_admitted() {
        let p = case(
            r#"[{"kind":"define","place":"x"},{"kind":"borrow","place":"x","loan":"a","mutable":false},{"kind":"end_borrow","loan":"a"},{"kind":"compute","units":2},{"kind":"cooperate"},{"kind":"compute","units":3}]"#,
            Some(3),
        );
        let r = analyze_safety(&p, SafetyProfile::Hard);
        assert!(r.admitted_to_static_gate, "{:?}", r.diagnostics);
        assert!(!r.hard_realtime_certified);
    }
    #[test]
    fn exclusive_loan_conflict_rejected() {
        let p = case(
            r#"[{"kind":"define","place":"x"},{"kind":"borrow","place":"x","loan":"a","mutable":false},{"kind":"borrow","place":"x","loan":"b","mutable":true}]"#,
            Some(50),
        );
        assert!(codes(&p, SafetyProfile::General).contains(&"ORES-SAF104"));
    }
    #[test]
    fn moved_place_rejected() {
        let p = case(
            r#"[{"kind":"define","place":"x"},{"kind":"move","place":"x"},{"kind":"read","place":"x"}]"#,
            None,
        );
        assert!(codes(&p, SafetyProfile::General).contains(&"ORES-SAF101"));
    }
    #[test]
    fn suspension_with_live_loan_rejected() {
        let p = case(
            r#"[{"kind":"define","place":"x"},{"kind":"borrow","place":"x","loan":"a","mutable":false},{"kind":"suspend"}]"#,
            Some(10),
        );
        assert!(codes(&p, SafetyProfile::Hard).contains(&"ORES-SAF302"));
    }
    #[test]
    fn deadlock_lock_order_cycle_detected_globally() {
        let p: SafetyProgram = serde_json::from_str(r#"{"schema_version":1,"effects_complete":true,"functions":[
        {"name":"a","control_flow":"linear","max_uninterrupted_units":10,"allow_error_propagation":false,"events":[{"kind":"lock","id":"X"},{"kind":"lock","id":"Y"},{"kind":"unlock","id":"Y"},{"kind":"unlock","id":"X"}]},
        {"name":"b","control_flow":"linear","max_uninterrupted_units":10,"allow_error_propagation":false,"events":[{"kind":"lock","id":"Y"},{"kind":"lock","id":"X"},{"kind":"unlock","id":"X"},{"kind":"unlock","id":"Y"}]}]}"#).unwrap();
        assert!(codes(&p, SafetyProfile::Hard).contains(&"ORES-SAF204"));
    }
    #[test]
    fn lock_held_across_wait_rejected() {
        let p = case(
            r#"[{"kind":"lock","id":"X"},{"kind":"wait","bounded":true},{"kind":"unlock","id":"X"}]"#,
            Some(10),
        );
        assert!(codes(&p, SafetyProfile::General).contains(&"ORES-SAF202"));
    }
    #[test]
    fn cooperative_budget_is_enforced() {
        let p = case(
            r#"[{"kind":"compute","units":5},{"kind":"compute","units":6}]"#,
            Some(10),
        );
        assert!(codes(&p, SafetyProfile::Soft).contains(&"ORES-SAF301"));
    }
    #[test]
    fn unknown_compute_cost_rejected() {
        let p = case(r#"[{"kind":"compute","units":null}]"#, Some(10));
        assert!(codes(&p, SafetyProfile::Hard).contains(&"ORES-SAF300"));
    }
    #[test]
    fn unhandled_error_rejected() {
        let p = case(r#"[{"kind":"may_fail","error":"e1"}]"#, None);
        assert!(codes(&p, SafetyProfile::General).contains(&"ORES-SAF604"));
    }
    #[test]
    fn caught_error_admitted() {
        let p = case(
            r#"[{"kind":"may_fail","error":"e1"},{"kind":"catch","error":"e1"}]"#,
            Some(10),
        );
        assert!(analyze_safety(&p, SafetyProfile::Hard).admitted_to_static_gate);
    }
    #[test]
    fn unknown_call_fails_closed() {
        let p = case(r#"[{"kind":"call","target":"untrusted"}]"#, Some(10));
        assert!(codes(&p, SafetyProfile::Hard).contains(&"ORES-SAF500"));
    }
    #[test]
    fn unsupported_cfg_and_mutable_actor_export_rejected() {
        let p = case(
            r#"[{"kind":"define","place":"x"},{"kind":"actor_transfer","place":"x","mutable":true}]"#,
            Some(10),
        );
        assert!(codes(&p, SafetyProfile::General).contains(&"ORES-SAF106"));
        let mut bad = p;
        bad.functions[0].control_flow = "branch".to_owned();
        assert!(codes(&bad, SafetyProfile::General).contains(&"ORES-SAF003"));
    }
}
