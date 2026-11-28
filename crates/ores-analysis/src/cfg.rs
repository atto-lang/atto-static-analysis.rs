//! CFG-aware, fail-closed ownership and effect verifier for a bounded Oreslang MIR slice.
//! The producer remains untrusted. No claim of hard-RT certification or universal
//! deadlock freedom. Only acyclic, explicit, finite, scalar-place CFGs are admitted.
use crate::safety::{Event, SafetyDiagnostic, SafetyProfile};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const MAX_FUNCTIONS: usize = 256;
const MAX_BLOCKS: usize = 512;
const MAX_EVENTS: usize = 8192;
const MAX_IDENTIFIER: usize = 128;
const MAX_MODULE_BLOCKS: usize = 4096;
const MAX_MODULE_EVENTS: usize = 100_000;
const MAX_HELD_LOCKS: usize = 64;
const MAX_LOCK_ORDER_WORK: usize = 16_384;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CfgProgram {
    pub schema_version: u32,
    pub effects_complete: bool,
    pub functions: Vec<CfgFunction>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CfgFunction {
    pub name: String,
    pub entry: String,
    pub max_uninterrupted_units: Option<u64>,
    pub allow_error_propagation: bool,
    pub blocks: Vec<CfgBlock>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CfgBlock {
    pub id: String,
    pub events: Vec<Event>,
    pub terminator: Terminator,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Terminator {
    Return,
    Jump {
        target: String,
    },
    Branch {
        condition: String,
        then_block: String,
        else_block: String,
    },
}
#[derive(Debug, Serialize)]
pub struct CfgReport {
    pub schema_version: u32,
    pub assurance_scope: &'static str,
    pub admitted_to_static_gate: bool,
    pub hard_realtime_certified: bool,
    pub diagnostics: Vec<SafetyDiagnostic>,
    pub lock_order_edges: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Loan {
    place: String,
    mutable: bool,
}
#[derive(Clone, Debug, Default)]
struct Flow {
    /// A place is definitely usable only if owned on every incoming path.
    owned: BTreeMap<String, bool>,
    /// Defining block/event identity; branch-local definitions cannot be
    /// silently coalesced at a join without a validated phi/merge operation.
    origins: BTreeMap<String, String>,
    loans: BTreeMap<String, Loan>,
    held_locks: Vec<String>,
    pending_errors: BTreeSet<String>,
    uninterrupted: Option<u64>,
}
impl Flow {
    fn initial() -> Self {
        Self {
            uninterrupted: Some(0),
            ..Self::default()
        }
    }
    fn active_loans(&self, place: &str) -> (usize, usize) {
        self.loans.values().fold((0, 0), |(r, w), l| {
            if l.place == place {
                if l.mutable {
                    (r, w + 1)
                } else {
                    (r + 1, w)
                }
            } else {
                (r, w)
            }
        })
    }
    fn owned(&self, place: &str) -> bool {
        self.owned.get(place) == Some(&true)
    }
}
fn valid_identifier(s: &str) -> bool {
    s.len() <= MAX_IDENTIFIER
        && !s.is_empty()
        && s.as_bytes()
            .iter()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphabetic() || *b == b'_' || (i > 0 && b.is_ascii_digit()))
}
fn diagnostic(
    out: &mut Vec<SafetyDiagnostic>,
    code: &'static str,
    function: &str,
    event_index: Option<usize>,
    message: impl Into<String>,
) {
    out.push(SafetyDiagnostic {
        code,
        function: function.into(),
        event_index,
        message: message.into(),
        severity: "error",
    });
}
fn predecessors_and_order(
    function: &CfgFunction,
    output: &mut Vec<SafetyDiagnostic>,
) -> Option<(HashMap<String, usize>, Vec<String>)> {
    let name = &function.name;
    if function.blocks.is_empty()
        || function.blocks.len() > MAX_BLOCKS
        || function
            .blocks
            .iter()
            .map(|b| b.events.len())
            .sum::<usize>()
            > MAX_EVENTS
    {
        diagnostic(output, "ORES-CFG001", name, None, "empty or oversized CFG");
        return None;
    }
    let mut indexes = HashMap::new();
    for (i, block) in function.blocks.iter().enumerate() {
        if !valid_identifier(&block.id) || indexes.insert(block.id.clone(), i).is_some() {
            diagnostic(
                output,
                "ORES-CFG002",
                name,
                None,
                format!("invalid or duplicate block {}", block.id),
            );
            return None;
        }
    }
    if !indexes.contains_key(&function.entry) {
        diagnostic(
            output,
            "ORES-CFG003",
            name,
            None,
            "entry block does not exist",
        );
        return None;
    }
    let mut indegree = indexes
        .keys()
        .map(|k| (k.clone(), 0usize))
        .collect::<HashMap<_, _>>();
    let mut links: HashMap<String, Vec<String>> = HashMap::new();
    for block in &function.blocks {
        let targets: Vec<String> = match &block.terminator {
            Terminator::Return => Vec::new(),
            Terminator::Jump { target } => vec![target.clone()],
            Terminator::Branch {
                then_block,
                else_block,
                ..
            } => {
                if then_block == else_block {
                    diagnostic(
                        output,
                        "ORES-CFG004",
                        name,
                        None,
                        "duplicate branch successor",
                    );
                    return None;
                }
                vec![then_block.clone(), else_block.clone()]
            }
        };
        for target in &targets {
            if !indexes.contains_key(target) {
                diagnostic(
                    output,
                    "ORES-CFG005",
                    name,
                    None,
                    format!("missing successor {target}"),
                );
                return None;
            }
            *indegree.get_mut(target).expect("validated successor") += 1;
        }
        links.insert(block.id.clone(), targets);
    }
    if indegree.get(&function.entry) != Some(&0) {
        diagnostic(
            output,
            "ORES-CFG006",
            name,
            None,
            "entry has predecessor or cycle",
        );
        return None;
    }
    // Verify ALL blocks, not only those reachable from entry. Disconnected code
    // and unbounded/backward edges must never be silently omitted.
    let mut queue = BTreeSet::new();
    for (id, count) in &indegree {
        if *count == 0 {
            queue.insert(id.clone());
        }
    }
    let mut topological = Vec::new();
    while let Some(id) = queue.pop_first() {
        topological.push(id.clone());
        if let Some(next) = links.get(&id) {
            for target in next {
                let count = indegree.get_mut(target).expect("validated successor");
                *count -= 1;
                if *count == 0 {
                    queue.insert(target.clone());
                }
            }
        }
    }
    if topological.len() != function.blocks.len() {
        diagnostic(
            output,
            "ORES-CFG007",
            name,
            None,
            "cyclic CFG requires an independently proven loop bound",
        );
        return None;
    }
    if topological.first().map(String::as_str) != Some(function.entry.as_str()) {
        diagnostic(
            output,
            "ORES-CFG008",
            name,
            None,
            "unreachable or disconnected basic block",
        );
        return None;
    }
    // Reject any unreachable component, even if acyclic.
    let mut reached = HashSet::new();
    let mut stack = vec![function.entry.clone()];
    while let Some(id) = stack.pop() {
        if reached.insert(id.clone()) {
            if let Some(next) = links.get(&id) {
                stack.extend(next.iter().cloned());
            }
        }
    }
    if reached.len() != function.blocks.len() {
        diagnostic(
            output,
            "ORES-CFG008",
            name,
            None,
            "CFG has unreachable blocks",
        );
        return None;
    }
    Some((indexes, topological))
}
fn merge(
    old: &mut Flow,
    next: &Flow,
    name: &str,
    block: &str,
    diagnostics: &mut Vec<SafetyDiagnostic>,
) {
    let names: BTreeSet<String> = old.owned.keys().chain(next.owned.keys()).cloned().collect();
    let mut merged = BTreeMap::new();
    for place in names {
        merged.insert(place.clone(), old.owned(&place) && next.owned(&place));
    }
    for (place, usable) in &mut merged {
        if *usable && old.origins.get(place) != next.origins.get(place) {
            diagnostic(
                diagnostics, "ORES-CFG103", name, None,
                format!("incompatible defining sites for owned place {place} at join {block}; typed phi required"),
            );
            *usable = false;
        }
    }
    old.owned = merged;
    old.origins.retain(|place, origin| {
        old.owned.get(place) == Some(&true) && next.origins.get(place) == Some(origin)
    });
    if old.loans != next.loans {
        diagnostic(diagnostics, "ORES-CFG100", name, None,
            format!("incompatible live-loan sets at join {block}; require matched lifetimes on all paths"));
        // Remain conservative after detecting the error.
        old.loans.extend(next.loans.clone());
    }
    if old.held_locks != next.held_locks {
        diagnostic(
            diagnostics,
            "ORES-CFG101",
            name,
            None,
            format!("incompatible held-lock sets at join {block}"),
        );
    }
    if old.pending_errors != next.pending_errors {
        diagnostic(
            diagnostics,
            "ORES-CFG102",
            name,
            None,
            format!("incompatible unhandled-error sets at join {block}"),
        );
        old.pending_errors.extend(next.pending_errors.clone());
    }
    old.uninterrupted = match (old.uninterrupted, next.uninterrupted) {
        (Some(x), Some(y)) => Some(x.max(y)),
        _ => None,
    };
}
// A long lock-order chain must not consume a Rust call stack frame per edge.
// Kahn's algorithm detects a cycle even if a target has no outgoing edges.
fn lock_cycle(edges: &BTreeMap<String, BTreeSet<String>>) -> bool {
    let mut incoming: BTreeMap<&str, usize> = BTreeMap::new();
    for (from, targets) in edges {
        incoming.entry(from.as_str()).or_insert(0);
        for target in targets {
            *incoming.entry(target.as_str()).or_insert(0) += 1;
        }
    }

    let mut ready: BTreeSet<&str> = incoming
        .iter()
        .filter_map(|(&name, &count)| (count == 0).then_some(name))
        .collect();
    let mut visited = 0usize;
    while let Some(name) = ready.pop_first() {
        visited += 1;
        if let Some(targets) = edges.get(name) {
            for target in targets {
                let count = incoming.get_mut(target.as_str()).expect("indexed edge");
                *count -= 1;
                if *count == 0 {
                    ready.insert(target.as_str());
                }
            }
        }
    }
    visited != incoming.len()
}
pub fn analyze_cfg(program: &CfgProgram, profile: SafetyProfile) -> CfgReport {
    let mut diagnostics = Vec::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut lock_order_work = 0usize;
    if program.schema_version != 2
        || !program.effects_complete
        || program.functions.is_empty()
        || program.functions.len() > MAX_FUNCTIONS
    {
        diagnostic(
            &mut diagnostics,
            "ORES-CFG000",
            "<module>",
            None,
            "invalid schema, empty/oversized module or incomplete effects",
        );
        return CfgReport {
            schema_version: 2,
            assurance_scope: "acyclic_declared_scalar_cfg_only; no source-proof, WCET, scheduler or complete borrow verification",
            admitted_to_static_gate: false,
            hard_realtime_certified: false,
            diagnostics,
            lock_order_edges: BTreeMap::new(),
        };
    }
    // The per-function limits are not sufficient for direct library callers:
    // check the entire module before constructing per-block ownership states.
    let total_blocks = program.functions.iter().fold(0usize, |count, function| {
        count.saturating_add(function.blocks.len())
    });
    let total_events = program.functions.iter().fold(0usize, |count, function| {
        function
            .blocks
            .iter()
            .fold(count, |sum, block| sum.saturating_add(block.events.len()))
    });
    if total_blocks > MAX_MODULE_BLOCKS || total_events > MAX_MODULE_EVENTS {
        diagnostic(
            &mut diagnostics,
            "ORES-CFG010",
            "<module>",
            None,
            "global CFG block/event work budget exceeded",
        );
        return CfgReport {
            schema_version: 2,
            assurance_scope: "acyclic_declared_scalar_cfg_only; no source-proof, WCET, scheduler or complete borrow verification",
            admitted_to_static_gate: false,
            hard_realtime_certified: false,
            diagnostics,
            lock_order_edges: BTreeMap::new(),
        };
    }
    let mut names = HashSet::new();
    for f in &program.functions {
        if !valid_identifier(&f.name) || !names.insert(&f.name) {
            diagnostic(
                &mut diagnostics,
                "ORES-CFG009",
                &f.name,
                None,
                "invalid or repeated function",
            );
        }
        if profile != SafetyProfile::General && f.max_uninterrupted_units.is_none() {
            diagnostic(
                &mut diagnostics,
                "ORES-CFG300",
                &f.name,
                None,
                "missing cooperation budget",
            );
        }
        let Some((indexes, order)) = predecessors_and_order(f, &mut diagnostics) else {
            continue;
        };
        let mut incoming = HashMap::from([(f.entry.clone(), Flow::initial())]);
        for id in order {
            let Some(mut state) = incoming.remove(&id) else {
                diagnostic(
                    &mut diagnostics,
                    "ORES-CFG008",
                    &f.name,
                    None,
                    format!("no incoming state for block {id}"),
                );
                continue;
            };
            let block = &f.blocks[*indexes.get(&id).expect("validated block")];
            for (i, e) in block.events.iter().enumerate() {
                let at = Some(i);
                match e {
                    Event::Define { place } => {
                        if !valid_identifier(place) || state.owned.contains_key(place) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG110",
                                &f.name,
                                at,
                                "invalid/redefined place",
                            );
                        } else {
                            state.owned.insert(place.clone(), true);
                            state.origins.insert(place.clone(), format!("{id}:{i}"));
                        }
                    }
                    Event::Read { place } => {
                        if !state.owned(place) || state.active_loans(place).1 > 0 {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG111",
                                &f.name,
                                at,
                                format!("read while moved or exclusively loaned: {place}"),
                            );
                        }
                    }
                    Event::Write { place } => {
                        if !state.owned(place) || state.active_loans(place) != (0, 0) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG112",
                                &f.name,
                                at,
                                format!("write while moved/loaned: {place}"),
                            );
                        }
                    }
                    Event::Move { place } => {
                        if !state.owned(place) || state.active_loans(place) != (0, 0) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG113",
                                &f.name,
                                at,
                                format!("invalid move: {place}"),
                            );
                        } else {
                            state.owned.insert(place.clone(), false);
                        }
                    }
                    Event::Borrow {
                        place,
                        loan,
                        mutable,
                    } => {
                        let (shared, exclusive) = state.active_loans(place);
                        if !state.owned(place)
                            || !valid_identifier(loan)
                            || state.loans.contains_key(loan)
                            || (if *mutable {
                                shared + exclusive > 0
                            } else {
                                exclusive > 0
                            })
                        {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG114",
                                &f.name,
                                at,
                                "conflicting/invalid loan",
                            );
                        } else {
                            state.loans.insert(
                                loan.clone(),
                                Loan {
                                    place: place.clone(),
                                    mutable: *mutable,
                                },
                            );
                        }
                    }
                    Event::EndBorrow { loan } => {
                        if state.loans.remove(loan).is_none() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG115",
                                &f.name,
                                at,
                                "unknown/end-twice loan",
                            );
                        }
                    }
                    Event::ActorTransfer { .. } => diagnostic(
                        &mut diagnostics,
                        "ORES-CFG116",
                        &f.name,
                        at,
                        "actor transfer requires checked domain/freeze/capability proof",
                    ),
                    Event::Lock { id: lock } => {
                        if !valid_identifier(lock) || state.held_locks.contains(lock) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG200",
                                &f.name,
                                at,
                                "invalid/reentrant lock",
                            );
                        } else if state.held_locks.len() >= MAX_HELD_LOCKS
                            || lock_order_work.saturating_add(state.held_locks.len())
                                > MAX_LOCK_ORDER_WORK
                        {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG206",
                                &f.name,
                                at,
                                "lock nesting or global lock-order graph budget exceeded",
                            );
                        } else {
                            // Count attempted pairs even when deduplicated:
                            // the construction effort itself is security-bounded.
                            lock_order_work += state.held_locks.len();
                            for held in &state.held_locks {
                                edges.entry(held.clone()).or_default().insert(lock.clone());
                            }
                            state.held_locks.push(lock.clone());
                        }
                    }
                    Event::Unlock { id: lock } => {
                        if state.held_locks.last() != Some(lock) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG201",
                                &f.name,
                                at,
                                "non-LIFO or missing lock release",
                            );
                        } else {
                            state.held_locks.pop();
                        }
                    }
                    Event::Cooperate => {
                        // Without a verified pinned-continuation proof, a
                        // cooperative yield cannot cross live loans or locks.
                        if !state.held_locks.is_empty() || !state.loans.is_empty() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG202",
                                &f.name,
                                at,
                                "cooperate with live loans or held locks",
                            );
                        } else {
                            state.uninterrupted = Some(0);
                        }
                    }
                    Event::Suspend => {
                        if !state.loans.is_empty() || !state.held_locks.is_empty() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG203",
                                &f.name,
                                at,
                                "suspend with live loans/locks",
                            );
                        }
                        state.uninterrupted = Some(0);
                    }
                    Event::Compute { units } => {
                        if *units == Some(0) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG303",
                                &f.name,
                                at,
                                "zero-cost compute event cannot attest work",
                            );
                        }
                        state.uninterrupted = state
                            .uninterrupted
                            .and_then(|old| old.checked_add((*units)?));
                        if state.uninterrupted.is_none() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG301",
                                &f.name,
                                at,
                                "unknown/overflowed work bound",
                            );
                        } else if profile != SafetyProfile::General
                            && matches!((state.uninterrupted, f.max_uninterrupted_units), (Some(x), Some(y)) if x > y)
                        {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG302",
                                &f.name,
                                at,
                                "cooperation budget exceeded",
                            );
                        }
                    }
                    Event::Wait { bounded } => {
                        if !bounded || !state.held_locks.is_empty() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG204",
                                &f.name,
                                at,
                                "unbounded wait / wait under lock",
                            );
                        }
                    }
                    Event::Allocate { bytes } => {
                        if profile == SafetyProfile::Hard && *bytes != Some(0) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG400",
                                &f.name,
                                at,
                                "hard-RT allocation restriction",
                            );
                        } else if profile == SafetyProfile::Soft && bytes.is_none() {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG400",
                                &f.name,
                                at,
                                "unknown soft-RT allocation",
                            );
                        }
                    }
                    Event::UnsafeFfi => diagnostic(
                        &mut diagnostics,
                        "ORES-CFG401",
                        &f.name,
                        at,
                        "unchecked FFI contract",
                    ),
                    Event::Call { .. } => diagnostic(
                        &mut diagnostics,
                        "ORES-CFG402",
                        &f.name,
                        at,
                        "call lacks compositional proof summary",
                    ),
                    Event::MayFail { error } => {
                        if !valid_identifier(error) || !state.pending_errors.insert(error.clone()) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG500",
                                &f.name,
                                at,
                                "invalid/repeated fallible effect",
                            );
                        }
                    }
                    Event::Catch { error } => {
                        if !state.pending_errors.remove(error) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG501",
                                &f.name,
                                at,
                                "catch without active error",
                            );
                        }
                    }
                    Event::Propagate { error } => {
                        if !f.allow_error_propagation || !state.pending_errors.remove(error) {
                            diagnostic(
                                &mut diagnostics,
                                "ORES-CFG502",
                                &f.name,
                                at,
                                "unapproved propagation",
                            );
                        }
                    }
                    Event::Panic => diagnostic(
                        &mut diagnostics,
                        "ORES-CFG503",
                        &f.name,
                        at,
                        "unchecked panic/supervision path",
                    ),
                }
            }
            let targets = match &block.terminator {
                Terminator::Return => {
                    if !state.loans.is_empty()
                        || !state.held_locks.is_empty()
                        || !state.pending_errors.is_empty()
                    {
                        diagnostic(
                            &mut diagnostics,
                            "ORES-CFG510",
                            &f.name,
                            None,
                            format!("unreleased loan/lock/error at return of {id}"),
                        );
                    }
                    Vec::new()
                }
                Terminator::Jump { target } => vec![target],
                Terminator::Branch {
                    condition,
                    then_block,
                    else_block,
                } => {
                    if !state.owned(condition) || state.active_loans(condition).1 > 0 {
                        diagnostic(
                            &mut diagnostics,
                            "ORES-CFG120",
                            &f.name,
                            None,
                            format!("branch reads unavailable condition {condition}"),
                        );
                    }
                    vec![then_block, else_block]
                }
            };
            for target in targets {
                if let Some(existing) = incoming.get_mut(target) {
                    merge(existing, &state, &f.name, target, &mut diagnostics);
                } else {
                    incoming.insert(target.clone(), state.clone());
                }
            }
        }
    }
    if lock_cycle(&edges) {
        diagnostic(
            &mut diagnostics,
            "ORES-CFG205",
            "<module>",
            None,
            "global lock-order cycle",
        );
    }
    diagnostics.sort_by(|a, b| {
        (
            a.function.as_str(),
            a.event_index,
            a.code,
            a.message.as_str(),
        )
            .cmp(&(
                b.function.as_str(),
                b.event_index,
                b.code,
                b.message.as_str(),
            ))
    });
    CfgReport {
        schema_version: 2,
        assurance_scope: "acyclic_declared_scalar_cfg_only; no source-proof, WCET, scheduler or complete borrow verification",
        admitted_to_static_gate: diagnostics.is_empty(),
        hard_realtime_certified: false,
        diagnostics,
        lock_order_edges: edges.into_iter().map(|(k,v)| (k,v.into_iter().collect())).collect(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn run(body: &str, mode: SafetyProfile) -> CfgReport {
        let program: CfgProgram = serde_json::from_str(body).unwrap();
        analyze_cfg(&program, mode)
    }
    fn base(blocks: &str) -> String {
        format!(
            r#"{{"schema_version":2,"effects_complete":true,"functions":[{{"name":"f","entry":"a","max_uninterrupted_units":10,"allow_error_propagation":false,"blocks":{blocks}}}]}}"#
        )
    }
    fn has(r: &CfgReport, code: &str) -> bool {
        r.diagnostics.iter().any(|d| d.code == code)
    }
    #[test]
    fn oversized_function_manifest_exits_before_cfg_traversal() {
        let mut program: CfgProgram = serde_json::from_str(&base(
            r#"[{"id":"a","events":[],"terminator":{"kind":"return"}}]"#,
        ))
        .unwrap();
        while program.functions.len() <= MAX_FUNCTIONS {
            program.functions.push(CfgFunction {
                name: format!("f{}", program.functions.len()),
                entry: "a".into(),
                max_uninterrupted_units: Some(10),
                allow_error_propagation: false,
                blocks: Vec::new(),
            });
        }
        let report = analyze_cfg(&program, SafetyProfile::General);
        assert!(!report.admitted_to_static_gate);
        assert!(has(&report, "ORES-CFG000"));
        assert_eq!(report.diagnostics.len(), 1);
    }

    #[test]
    fn global_event_budget_is_enforced_for_library_callers() {
        let mut p: CfgProgram = serde_json::from_str(&base(
            r#"[{"id":"a","events":[],"terminator":{"kind":"return"}}]"#,
        ))
        .unwrap();
        p.functions[0].blocks[0].events = std::iter::repeat_with(|| Event::Cooperate)
            .take(MAX_MODULE_EVENTS + 1)
            .collect();
        let r = analyze_cfg(&p, SafetyProfile::General);
        assert!(!r.admitted_to_static_gate);
        assert!(has(&r, "ORES-CFG010"));
        assert!(!r.hard_realtime_certified);
    }

    #[test]
    fn straight_line_valid() {
        let r = run(
            &base(
                r#"[{"id":"a","events":[{"kind":"define","place":"x"},{"kind":"read","place":"x"}],"terminator":{"kind":"return"}}]"#,
            ),
            SafetyProfile::Hard,
        );
        assert!(r.admitted_to_static_gate, "{:?}", r.diagnostics);
        assert!(!r.hard_realtime_certified);
    }
    #[test]
    fn valid_diamond_with_balanced_borrows() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[{"kind":"define","place":"x"},{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
          {"id":"b","events":[{"kind":"borrow","place":"x","loan":"r","mutable":false},{"kind":"end_borrow","loan":"r"}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"c","events":[{"kind":"read","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"d","events":[{"kind":"read","place":"x"}],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::Hard,
        );
        assert!(r.admitted_to_static_gate, "{:?}", r.diagnostics);
    }
    #[test]
    fn use_after_move_across_branch_rejected() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[{"kind":"define","place":"x"},{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
          {"id":"b","events":[{"kind":"move","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"c","events":[],"terminator":{"kind":"jump","target":"d"}},
          {"id":"d","events":[{"kind":"read","place":"x"}],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG111"), "{:?}", r.diagnostics);
    }
    #[test]
    fn different_branch_definitions_require_validated_phi() {
        let r = run(
            &base(
                r#"[
              {"id":"a","events":[{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
              {"id":"b","events":[{"kind":"define","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
              {"id":"c","events":[{"kind":"define","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
              {"id":"d","events":[{"kind":"read","place":"x"}],"terminator":{"kind":"return"}}
            ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG103"), "{:?}", r.diagnostics);
        assert!(has(&r, "ORES-CFG111"), "{:?}", r.diagnostics);
    }
    #[test]
    fn different_branch_definitions_are_not_reconciled_by_join_order() {
        let r = run(
            &base(
                r#"[
              {"id":"a","events":[{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"z","else_block":"b"}},
              {"id":"z","events":[{"kind":"define","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
              {"id":"b","events":[{"kind":"define","place":"x"}],"terminator":{"kind":"jump","target":"d"}},
              {"id":"d","events":[{"kind":"read","place":"x"}],"terminator":{"kind":"return"}}
            ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG103"), "{:?}", r.diagnostics);
    }
    #[test]
    fn live_loan_disagreement_at_join_rejected() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[{"kind":"define","place":"x"},{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
          {"id":"b","events":[{"kind":"borrow","place":"x","loan":"r","mutable":false}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"c","events":[],"terminator":{"kind":"jump","target":"d"}},
          {"id":"d","events":[],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG100"));
    }
    #[test]
    fn max_path_cost_not_sum_and_cooperation_budget() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
          {"id":"b","events":[{"kind":"compute","units":7}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"c","events":[{"kind":"compute","units":9}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"d","events":[{"kind":"compute","units":2}],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::Hard,
        );
        assert!(has(&r, "ORES-CFG302"), "{:?}", r.diagnostics);
    }
    #[test]
    fn cycles_rejected_not_assumed_bounded() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[],"terminator":{"kind":"jump","target":"b"}},
          {"id":"b","events":[{"kind":"cooperate"}],"terminator":{"kind":"jump","target":"b"}}
        ]"#,
            ),
            SafetyProfile::Hard,
        );
        assert!(has(&r, "ORES-CFG007"));
    }
    #[test]
    fn unreachable_and_missing_block_rejected() {
        let x = run(
            &base(
                r#"[
          {"id":"a","events":[],"terminator":{"kind":"return"}},
          {"id":"b","events":[],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&x, "ORES-CFG008"));
        let y = run(
            &base(r#"[{"id":"a","events":[],"terminator":{"kind":"jump","target":"z"}}]"#),
            SafetyProfile::General,
        );
        assert!(has(&y, "ORES-CFG005"));
    }
    #[test]
    fn loan_across_suspend_and_conflicts_rejected() {
        let r = run(
            &base(
                r#"[{"id":"a","events":[
          {"kind":"define","place":"x"},
          {"kind":"borrow","place":"x","loan":"r","mutable":false},
          {"kind":"borrow","place":"x","loan":"w","mutable":true},
          {"kind":"suspend"},
          {"kind":"end_borrow","loan":"r"}
        ],"terminator":{"kind":"return"}}]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG114"));
        assert!(has(&r, "ORES-CFG203"));
    }
    #[test]
    fn zero_cost_compute_is_rejected_by_every_profile() {
        let fixture = base(
            r#"[{"id":"a","events":[{"kind":"compute","units":0}],"terminator":{"kind":"return"}}]"#,
        );
        for profile in [SafetyProfile::General, SafetyProfile::Soft, SafetyProfile::Hard] {
            let report = run(&fixture, profile);
            assert!(has(&report, "ORES-CFG303"));
            assert!(!report.admitted_to_static_gate);
        }
    }

    #[test]
    fn unknown_call_does_not_get_safety_certificate() {
        let r = run(
            &base(
                r#"[{"id":"a","events":[{"kind":"call","target":"callee"}],"terminator":{"kind":"return"}}]"#,
            ),
            SafetyProfile::Hard,
        );
        assert!(has(&r, "ORES-CFG402"));
        assert!(!r.hard_realtime_certified);
    }
    #[test]
    fn lock_depth_limit_rejects_quadratic_graph_growth() {
        let mut p: CfgProgram = serde_json::from_str(&base(
            r#"[{"id":"a","events":[],"terminator":{"kind":"return"}}]"#,
        ))
        .unwrap();
        p.functions[0].blocks[0].events = (0..=MAX_HELD_LOCKS)
            .map(|i| Event::Lock {
                id: format!("L{i}"),
            })
            .collect();
        let r = analyze_cfg(&p, SafetyProfile::General);
        assert!(has(&r, "ORES-CFG206"));
        assert!(!r.admitted_to_static_gate);
    }

    #[test]
    fn global_lock_order_work_limit_rejects_repeated_acquisitions() {
        let mut p: CfgProgram = serde_json::from_str(&base(
            r#"[{"id":"a","events":[],"terminator":{"kind":"return"}}]"#,
        ))
        .unwrap();
        let mut events = Vec::new();
        for repeat in 0..10 {
            for level in 0..MAX_HELD_LOCKS {
                events.push(Event::Lock {
                    id: format!("L{repeat}_{level}"),
                });
            }
            for level in (0..MAX_HELD_LOCKS).rev() {
                events.push(Event::Unlock {
                    id: format!("L{repeat}_{level}"),
                });
            }
        }
        p.functions[0].blocks[0].events = events;
        let report = analyze_cfg(&p, SafetyProfile::General);
        assert!(has(&report, "ORES-CFG206"));
        assert!(!report.admitted_to_static_gate);
    }

    #[test]
    fn deep_lock_order_graph_is_checked_without_recursive_dfs() {
        let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for i in 0..10_000 {
            edges
                .entry(format!("L{i}"))
                .or_default()
                .insert(format!("L{}", i + 1));
        }
        assert!(!lock_cycle(&edges), "a long path is not a cycle");
        edges
            .entry("L10000".into())
            .or_default()
            .insert("L0".into());
        assert!(lock_cycle(&edges), "the closing edge creates a cycle");
    }

    #[test]
    fn lock_cycle_across_functions_rejected() {
        let x = r#"{"schema_version":2,"effects_complete":true,"functions":[
          {"name":"f","entry":"a","max_uninterrupted_units":10,"allow_error_propagation":false,
          "blocks":[{"id":"a","events":[{"kind":"lock","id":"X"},{"kind":"lock","id":"Y"},{"kind":"unlock","id":"Y"},{"kind":"unlock","id":"X"}],"terminator":{"kind":"return"}}]},
          {"name":"g","entry":"a","max_uninterrupted_units":10,"allow_error_propagation":false,
          "blocks":[{"id":"a","events":[{"kind":"lock","id":"Y"},{"kind":"lock","id":"X"},{"kind":"unlock","id":"X"},{"kind":"unlock","id":"Y"}],"terminator":{"kind":"return"}}]}
        ]}"#;
        assert!(has(&run(x, SafetyProfile::General), "ORES-CFG205"));
    }
    #[test]
    fn cooperative_yield_rejects_live_loan_even_when_later_released() {
        let r = run(
            &base(r#"[{"id":"a","events":[{"kind":"define","place":"x"},{"kind":"borrow","place":"x","loan":"l","mutable":false},{"kind":"cooperate"},{"kind":"end_borrow","loan":"l"}],"terminator":{"kind":"return"}}]"#),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG202"));
        assert!(!r.admitted_to_static_gate);
    }

    #[test]
    fn cooperative_yield_after_end_borrow_is_valid() {
        let r = run(
            &base(r#"[{"id":"a","events":[{"kind":"define","place":"x"},{"kind":"borrow","place":"x","loan":"l","mutable":false},{"kind":"end_borrow","loan":"l"},{"kind":"cooperate"}],"terminator":{"kind":"return"}}]"#),
            SafetyProfile::General,
        );
        assert!(r.admitted_to_static_gate, "{:?}", r.diagnostics);
    }

    #[test]
    fn error_paths_must_balance() {
        let r = run(
            &base(
                r#"[
          {"id":"a","events":[{"kind":"define","place":"cond"}],"terminator":{"kind":"branch","condition":"cond","then_block":"b","else_block":"c"}},
          {"id":"b","events":[{"kind":"may_fail","error":"e"}],"terminator":{"kind":"jump","target":"d"}},
          {"id":"c","events":[],"terminator":{"kind":"jump","target":"d"}},
          {"id":"d","events":[],"terminator":{"kind":"return"}}
        ]"#,
            ),
            SafetyProfile::General,
        );
        assert!(has(&r, "ORES-CFG102"));
    }
}
