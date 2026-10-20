//! Experimental CFG-sensitive ownership / actor-domain admission.
//! This is a verifier of compiler-emitted MIR *claims*, not an independent proof
//! that the compiler correctly modeled source semantics or hardware WCET.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowProgram {
    pub schema_version: u32,
    pub effects_complete: bool,
    pub functions: Vec<FlowFunction>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowFunction {
    pub name: String,
    pub entry: String,
    pub max_uninterrupted_units: Option<u64>,
    pub blocks: Vec<BasicBlock>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicBlock {
    pub id: String,
    pub ops: Vec<FlowOp>,
    pub terminator: Terminator,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// Owned local value: no other actor may access its storage directly.
    Local,
    /// Mutable actor-heap object: only owning actor may access directly.
    ActorPrivate,
    /// A previously verified frozen capability. Provenance is a compiler obligation.
    SharedImmutable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transfer {
    /// The compiler must have independently validated serialization and copy effects.
    SerializedMove,
    /// The frontend must prove immutability, lifetime and authorized domain.
    SharedCapability,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FlowOp {
    Declare { place: String, domain: Domain },
    Read { place: String },
    Write { place: String },
    Move { place: String },
    Borrow { place: String, loan: String, mutable: bool },
    EndBorrow { loan: String },
    ActorSend { place: String, transfer: Transfer },
    CriticalEnter { id: String },
    CriticalLeave { id: String },
    Compute { units: Option<u64> },
    Allocate { bytes: Option<u64> },
    Cooperate,
    Suspend,
    /// Interprocedural summaries are not yet verified by this CFG analyzer.
    Call { target: String },
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Terminator {
    Return,
    Jump { target: String },
    Branch { then_target: String, else_target: String },
}
impl Terminator {
    fn targets(&self) -> Vec<&str> {
        match self {
            Self::Return => vec![],
            Self::Jump { target } => vec![target],
            Self::Branch { then_target, else_target } => {
                if then_target == else_target {
                    vec![then_target]
                } else {
                    vec![then_target, else_target]
                }
            }
        }
    }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlowProfile {
    General,
    Soft,
    Hard,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Place {
    domain: Domain,
    available: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    places: BTreeMap<String, Place>,
    loans: BTreeMap<String, (String, bool)>,
    critical: Vec<String>,
    since_checkpoint: Option<u64>,
}
impl State {
    fn entry() -> Self {
        Self {
            places: BTreeMap::new(),
            loans: BTreeMap::new(),
            critical: vec![],
            since_checkpoint: Some(0),
        }
    }
    fn loan_counts(&self, place: &str) -> (usize, usize) {
        let mut shared = 0;
        let mut mutable = 0;
        for (name, is_mutable) in self.loans.values() {
            if name == place {
                if *is_mutable { mutable += 1 } else { shared += 1 }
            }
        }
        (shared, mutable)
    }
    fn available(&self, place: &str) -> bool {
        self.places.get(place).is_some_and(|p| p.available)
    }
    /// Path joins require identical ownership/loan/critical state.
    /// Independent path work is joined by maximum, never minimum/sum.
    fn join(&mut self, incoming: &Self) -> bool {
        if self.places != incoming.places
            || self.loans != incoming.loans
            || self.critical != incoming.critical
        {
            return false;
        }
        self.since_checkpoint = match (self.since_checkpoint, incoming.since_checkpoint) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        true
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct FlowDiagnostic {
    pub code: &'static str,
    pub function: String,
    pub block: String,
    pub operation: Option<usize>,
    pub message: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct FlowReport {
    pub schema_version: u32,
    pub assurance_scope: &'static str,
    pub admitted_to_static_gate: bool,
    pub hard_realtime_certified: bool,
    pub diagnostics: Vec<FlowDiagnostic>,
}
fn error(
    diagnostics: &mut Vec<FlowDiagnostic>,
    code: &'static str,
    function: &str,
    block: &str,
    operation: Option<usize>,
    message: impl Into<String>,
) {
    diagnostics.push(FlowDiagnostic {
        code, function: function.into(), block: block.into(), operation,
        message: message.into(),
    });
}
fn step(
    state: &mut State,
    op: &FlowOp,
    profile: FlowProfile,
    limit: Option<u64>,
    diagnostics: &mut Vec<FlowDiagnostic>,
    function: &str,
    block: &str,
    index: usize,
) {
    let mut err = |code, reason| {
        error(diagnostics, code, function, block, Some(index), reason);
    };
    match op {
        FlowOp::Declare { place, domain } => {
            if place.trim().is_empty() || state.places.contains_key(place) {
                err("ORES-FLOW100", format!("invalid or redeclared place '{place}'"));
            } else {
                state.places.insert(place.clone(), Place { domain: *domain, available: true });
            }
        }
        FlowOp::Read { place } => {
            if !state.available(place) || state.loan_counts(place).1 > 0 {
                err("ORES-FLOW101", format!("read while unavailable/mutably borrowed: {place}"));
            }
        }
        FlowOp::Write { place } => {
            if !state.available(place) || state.loan_counts(place) != (0, 0)
                || state.places.get(place).is_some_and(|p| p.domain == Domain::SharedImmutable)
            {
                err("ORES-FLOW102", format!("write to borrowed, moved or frozen place: {place}"));
            }
        }
        FlowOp::Move { place } => {
            if !state.available(place) || state.loan_counts(place) != (0, 0) {
                err("ORES-FLOW103", format!("move while borrowed/moved/unavailable: {place}"));
            } else if let Some(value) = state.places.get_mut(place) {
                value.available = false;
            }
        }
        FlowOp::Borrow { place, loan, mutable } => {
            let (shared, exclusive) = state.loan_counts(place);
            if loan.trim().is_empty() || state.loans.contains_key(loan)
                || !state.available(place)
                || (*mutable && (shared > 0 || exclusive > 0))
                || (!*mutable && exclusive > 0)
                || (*mutable && state.places.get(place).is_some_and(|p| p.domain == Domain::SharedImmutable))
            {
                err("ORES-FLOW104", format!("conflicting or invalid borrow '{loan}' of {place}"));
            } else {
                state.loans.insert(loan.clone(), (place.clone(), *mutable));
            }
        }
        FlowOp::EndBorrow { loan } => {
            if state.loans.remove(loan).is_none() {
                err("ORES-FLOW105", format!("loan already ended or absent: {loan}"));
            }
        }
        FlowOp::ActorSend { place, transfer } => {
            if !state.available(place) || state.loan_counts(place) != (0, 0) {
                err("ORES-FLOW106", format!("actor transfer requires exclusive live owner: {place}"));
            } else {
                match (state.places.get(place).map(|p| p.domain), transfer) {
                    (Some(Domain::SharedImmutable), Transfer::SharedCapability) => {}
                    (Some(Domain::Local | Domain::ActorPrivate), Transfer::SerializedMove) => {
                        if let Some(value) = state.places.get_mut(place) {
                            value.available = false;
                        }
                    }
                    _ => err("ORES-FLOW107", format!(
                        "invalid actor transfer mode or domain for '{place}'"
                    )),
                }
            }
        }
        FlowOp::CriticalEnter { id } => {
            if id.trim().is_empty() || state.critical.contains(id) {
                err("ORES-FLOW200", format!("reentrant/invalid critical region: {id}"));
            } else {
                state.critical.push(id.clone());
            }
        }
        FlowOp::CriticalLeave { id } => {
            if state.critical.last() != Some(id) {
                err("ORES-FLOW201", format!("critical region must close in LIFO order: {id}"));
            } else {
                state.critical.pop();
            }
        }
        FlowOp::Compute { units } => {
            state.since_checkpoint = state.since_checkpoint.and_then(|x| x.checked_add((*units)?));
            if profile == FlowProfile::Hard && state.since_checkpoint.is_none() {
                err("ORES-FLOW300", "unknown or overflowing compute-work bound".into());
            }
            if profile != FlowProfile::General {
                if let (Some(work), Some(max)) = (state.since_checkpoint, limit) {
                    if work > max {
                        err("ORES-FLOW301", format!("uninterrupted work {work} exceeds {max} abstract units"));
                    }
                }
            }
        }
        FlowOp::Allocate { bytes } => {
            if profile == FlowProfile::Hard && *bytes != Some(0) {
                err("ORES-FLOW400", "hard-RT function allocation-free bound unproven".into());
            }
        }
        FlowOp::Cooperate => state.since_checkpoint = Some(0),
        FlowOp::Suspend => {
            if !state.loans.is_empty() || !state.critical.is_empty() {
                err("ORES-FLOW302", "suspension with outstanding loans or critical regions".into());
            }
            state.since_checkpoint = Some(0);
        }
        FlowOp::Call { target } => {
            err("ORES-FLOW500", format!(
                "call '{target}' lacks integrated interprocedural ownership/effect summary"
            ));
        }
    }
}
pub fn analyze_flow(program: &FlowProgram, profile: FlowProfile) -> FlowReport {
    let mut diagnostics = Vec::new();
    if program.schema_version != 1 || !program.effects_complete {
        error(&mut diagnostics, "ORES-FLOW001", "<module>", "", None,
            "unsupported schema or effects_complete is false");
    }
    if program.functions.is_empty() || program.functions.len() > 4096 {
        error(&mut diagnostics, "ORES-FLOW002", "<module>", "", None,
            "invalid function count");
    }
    let mut seen_functions = HashSet::new();
    for function in &program.functions {
        if function.name.trim().is_empty() || !seen_functions.insert(&function.name) {
            error(&mut diagnostics, "ORES-FLOW002", &function.name, "", None,
                "blank or duplicate function name");
        }
        if profile == FlowProfile::Hard && function.max_uninterrupted_units.is_none() {
            error(&mut diagnostics, "ORES-FLOW300", &function.name, "", None,
                "hard-RT requires explicit uninterrupted-work budget");
        }
        if function.blocks.is_empty() || function.blocks.len() > 4096
            || function.blocks.iter().map(|b| b.ops.len()).sum::<usize>() > 100_000 {
            error(&mut diagnostics, "ORES-FLOW003", &function.name, "", None,
                "empty or oversized CFG");
            continue;
        }
        let mut by_id = HashMap::new();
        for block in &function.blocks {
            if block.id.trim().is_empty() || by_id.insert(block.id.as_str(), block).is_some() {
                error(&mut diagnostics, "ORES-FLOW004", &function.name, &block.id, None,
                    "blank or duplicate block id");
            }
        }
        if !by_id.contains_key(function.entry.as_str()) {
            error(&mut diagnostics, "ORES-FLOW005", &function.name, &function.entry, None,
                "entry block missing");
            continue;
        }
        let mut indegree: HashMap<&str, usize> = by_id.keys().map(|id| (*id, 0)).collect();
        let mut invalid_edges = false;
        for block in &function.blocks {
            for target in block.terminator.targets() {
                if let Some(count) = indegree.get_mut(target) {
                    *count += 1;
                } else {
                    invalid_edges = true;
                    error(&mut diagnostics, "ORES-FLOW006", &function.name, &block.id, None,
                        format!("missing successor block: {target}"));
                }
            }
        }
        if invalid_edges { continue; }
        // Only acyclic CFG is admitted until a loop invariant/fixed-point engine exists.
        let mut queue: VecDeque<&str> = indegree.iter()
            .filter(|(_, n)| **n == 0).map(|(id, _)| *id).collect();
        let mut order = Vec::new();
        while let Some(id) = queue.pop_front() {
            order.push(id);
            for target in by_id[id].terminator.targets() {
                let n = indegree.get_mut(target).expect("validated edge");
                *n -= 1;
                if *n == 0 { queue.push_back(target); }
            }
        }
        if order.len() != function.blocks.len() {
            error(&mut diagnostics, "ORES-FLOW007", &function.name, "", None,
                "cyclic CFG requires independently proved loop invariants/bounds");
            continue;
        }
        let mut incoming: HashMap<&str, State> = HashMap::new();
        incoming.insert(&function.entry, State::entry());
        for id in order {
            let Some(mut state) = incoming.remove(id) else {
                error(&mut diagnostics, "ORES-FLOW008", &function.name, id, None,
                    "unreachable basic block");
                continue;
            };
            let block = by_id[id];
            for (index, op) in block.ops.iter().enumerate() {
                step(&mut state, op, profile, function.max_uninterrupted_units,
                    &mut diagnostics, &function.name, id, index);
            }
            if matches!(block.terminator, Terminator::Return) {
                if !state.loans.is_empty() || !state.critical.is_empty() {
                    error(&mut diagnostics, "ORES-FLOW202", &function.name, id, None,
                        "function exits with outstanding loans or critical regions");
                }
            }
            for target in block.terminator.targets() {
                if let Some(existing) = incoming.get_mut(target) {
                    if !existing.join(&state) {
                        error(&mut diagnostics, "ORES-FLOW330", &function.name, target, None,
                            "join has disagreeing ownership, loans, domains or critical state");
                    }
                } else {
                    incoming.insert(target, state.clone());
                }
            }
        }
    }
    diagnostics.sort_by(|a, b| {
        (&a.function, &a.block, a.operation, a.code, &a.message).cmp(
            &(&b.function, &b.block, b.operation, b.code, &b.message))
    });
    FlowReport {
        schema_version: 1,
        assurance_scope: "compiler-emitted acyclic CFG contract only; not verified WCET",
        admitted_to_static_gate: diagnostics.is_empty(),
        hard_realtime_certified: false,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(json: &str) -> FlowReport {
        let program: FlowProgram = serde_json::from_str(json).unwrap();
        analyze_flow(&program, FlowProfile::Hard)
    }
    const SAFE: &str = r#"{"schema_version":1,"effects_complete":true,"functions":[{
        "name":"tick","entry":"entry","max_uninterrupted_units":4,
        "blocks":[
            {"id":"entry","ops":[{"kind":"declare","place":"x","domain":"actor_private"}],
             "terminator":{"kind":"branch","then_target":"left","else_target":"right"}},
            {"id":"left","ops":[{"kind":"compute","units":2}],
             "terminator":{"kind":"jump","target":"join"}},
            {"id":"right","ops":[{"kind":"compute","units":3}],
             "terminator":{"kind":"jump","target":"join"}},
            {"id":"join","ops":[{"kind":"read","place":"x"},{"kind":"compute","units":1}],
             "terminator":{"kind":"return"}}
        ]}]}"#;
    #[test] fn balanced_diamond_admitted_and_budget_uses_max_path() {
        assert!(run(SAFE).admitted_to_static_gate, "{:?}", run(SAFE).diagnostics);
    }
    #[test] fn joined_path_budget_detects_exceeding_maximum() {
        let bad = SAFE.replace(r#""max_uninterrupted_units":4"#, r#""max_uninterrupted_units":3"#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW301"));
    }
    #[test] fn rejects_branch_local_move_at_join() {
        let bad = SAFE.replace(
            r#""id":"left","ops":[{"kind":"compute","units":2}]"#,
            r#""id":"left","ops":[{"kind":"move","place":"x"}]"#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW330"));
    }
    #[test] fn detects_use_after_move() {
        let bad = SAFE.replace(r#""kind":"read","place":"x""#,
            r#" "kind":"move","place":"x"},{"kind":"read","place":"x""#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW101"));
    }
    #[test] fn rejects_mutable_aliasing() {
        let bad = SAFE.replace(r#""kind":"read","place":"x""#,
            r#" "kind":"borrow","place":"x","loan":"a","mutable":true},{"kind":"borrow","place":"x","loan":"b","mutable":false"#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW104"));
    }
    #[test] fn rejects_suspend_during_borrow() {
        let bad = SAFE.replace(r#""kind":"read","place":"x""#,
            r#" "kind":"borrow","place":"x","loan":"a","mutable":false},{"kind":"suspend""#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW302"));
    }
    #[test] fn prevents_private_zero_copy_actor_share() {
        let bad = SAFE.replace(r#""kind":"read","place":"x""#,
            r#" "kind":"actor_send","place":"x","transfer":"shared_capability""#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW107"));
    }
    #[test] fn fail_closed_on_cfg_cycles() {
        let bad = SAFE.replace(r#""id":"join","ops""#, r#""id":"join","ops""#)
            .replace(r#""id":"join","ops":[{"kind":"read""#, r#""id":"join","ops":[{"kind":"read""#)
            .replace(r#""terminator":{"kind":"return"}}"#, r#""terminator":{"kind":"jump","target":"entry"}}"#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW007"));
    }
    #[test] fn incomplete_manifest_is_never_admitted() {
        let bad = SAFE.replace(r#""effects_complete":true"#, r#""effects_complete":false"#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW001"));
    }
    #[test] fn incomplete_calls_are_never_admitted() {
        let bad = SAFE.replace(r#""kind":"read","place":"x""#,
            r#" "kind":"call","target":"callee""#);
        assert!(run(&bad).diagnostics.iter().any(|d| d.code == "ORES-FLOW500"));
    }
}
