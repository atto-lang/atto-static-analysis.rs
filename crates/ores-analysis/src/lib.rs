//! Prototype, versioned MIR-effect static analyzer for all Oreslang frontends.
//! Conservative on absent bounds and unresolvable callees. No proof of WCET.
pub mod safety;
pub mod cfg;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub schema_version: u32,
    pub functions: Vec<Function>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub name: String,
    pub operations: Vec<Operation>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Allocate {
        bytes: Option<u64>,
    },
    Copy {
        bytes: Option<u64>,
    },
    /// Abstract compute units from a checked language-level MIR, not cycles/WCET.
    Compute {
        units: Option<u64>,
    },
    BlockingIo,
    UnboundedWait,
    UnsafeFfi,
    Suspend,
    Call {
        target: String,
    },
    IndirectCall,
    Loop {
        iterations: Option<u64>,
        operations: Vec<Operation>,
    },
    /// A writable reference may not escape the owning actor's domain.
    ShareMutable {
        crosses_actor_boundary: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    General,
    SoftRealtime,
    HardRealtime,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// None means unproven/unknown, not zero.
    pub allocations_upper_bound: Option<u64>,
    pub copies_upper_bound: Option<u64>,
    /// Abstract operation count, NOT cycles or WCET.
    pub operations_upper_bound: Option<u64>,
    pub may_block: bool,
    pub may_wait_unbounded: bool,
    pub may_use_unsafe_ffi: bool,
    pub may_suspend: bool,
    pub may_mutate_foreign_actor: bool,
    pub unresolved_control_flow: bool,
}
impl Summary {
    fn zero() -> Self {
        Self {
            allocations_upper_bound: Some(0),
            copies_upper_bound: Some(0),
            operations_upper_bound: Some(0),
            ..Self::default()
        }
    }
    fn add_assign(&mut self, rhs: &Self) {
        self.allocations_upper_bound =
            add(self.allocations_upper_bound, rhs.allocations_upper_bound);
        self.copies_upper_bound = add(self.copies_upper_bound, rhs.copies_upper_bound);
        self.operations_upper_bound = add(self.operations_upper_bound, rhs.operations_upper_bound);
        self.may_block |= rhs.may_block;
        self.may_wait_unbounded |= rhs.may_wait_unbounded;
        self.may_use_unsafe_ffi |= rhs.may_use_unsafe_ffi;
        self.may_suspend |= rhs.may_suspend;
        self.may_mutate_foreign_actor |= rhs.may_mutate_foreign_actor;
        self.unresolved_control_flow |= rhs.unresolved_control_flow;
    }
    fn scale(&self, count: Option<u64>) -> Self {
        let mut scaled = self.clone();
        scaled.allocations_upper_bound = mul(self.allocations_upper_bound, count);
        scaled.copies_upper_bound = mul(self.copies_upper_bound, count);
        scaled.operations_upper_bound = mul(self.operations_upper_bound, count);
        // Unknown loop count is unbounded even if current body has no operations.
        scaled.unresolved_control_flow |= count.is_none();
        // A loop with zero iterations has no effects (even if its body is unsafe).
        if count == Some(0) {
            return Self::zero();
        }
        scaled
    }
}
fn add(lhs: Option<u64>, rhs: Option<u64>) -> Option<u64> {
    lhs?.checked_add(rhs?)
}
fn mul(lhs: Option<u64>, rhs: Option<u64>) -> Option<u64> {
    if lhs == Some(0) || rhs == Some(0) {
        Some(0)
    } else {
        lhs?.checked_mul(rhs?)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}
#[derive(Clone, Debug, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: Severity,
    pub function: String,
    pub message: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub diagnostics: Vec<Diagnostic>,
    pub functions: BTreeMap<String, Summary>,
}
impl Report {
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}
struct Engine<'a> {
    functions: HashMap<&'a str, &'a Function>,
    active: HashSet<String>,
    cache: HashMap<String, Summary>,
    diagnostics: Vec<Diagnostic>,
}
impl Engine<'_> {
    fn emit(
        &mut self,
        code: &'static str,
        severity: Severity,
        function: &str,
        message: impl Into<String>,
    ) {
        self.diagnostics.push(Diagnostic {
            code,
            severity,
            function: function.to_owned(),
            message: message.into(),
        });
    }
    fn function(&mut self, name: &str) -> Summary {
        if let Some(found) = self.cache.get(name) {
            return found.clone();
        }
        // Cycles require separately verified recursion bounds and stack limits;
        // intentionally reject instead of assuming a finite upper bound.
        if !self.active.insert(name.to_owned()) {
            self.emit(
                "ORES-SA102",
                Severity::Error,
                name,
                "recursive call cycle: bounds not proven",
            );
            return Summary {
                unresolved_control_flow: true,
                ..Summary::default()
            };
        }
        let result = match self.functions.get(name).copied() {
            Some(function) => self.operations(name, &function.operations),
            None => {
                self.emit(
                    "ORES-SA101",
                    Severity::Error,
                    name,
                    "callee is absent from effect IR",
                );
                Summary {
                    unresolved_control_flow: true,
                    ..Summary::default()
                }
            }
        };
        self.active.remove(name);
        self.cache.insert(name.to_owned(), result.clone());
        result
    }
    fn operations(&mut self, owner: &str, operations: &[Operation]) -> Summary {
        let mut summary = Summary::zero();
        for operation in operations {
            let mut effect = Summary::zero();
            effect.operations_upper_bound = Some(1);
            match operation {
                Operation::Allocate { bytes } => effect.allocations_upper_bound = *bytes,
                Operation::Copy { bytes } => effect.copies_upper_bound = *bytes,
                Operation::Compute { units } => effect.operations_upper_bound = *units,
                Operation::BlockingIo => effect.may_block = true,
                Operation::UnboundedWait => effect.may_wait_unbounded = true,
                Operation::UnsafeFfi => effect.may_use_unsafe_ffi = true,
                Operation::Suspend => effect.may_suspend = true,
                Operation::IndirectCall => {
                    effect = Summary {
                        unresolved_control_flow: true,
                        ..Summary::default()
                    };
                    self.emit(
                        "ORES-SA103",
                        Severity::Error,
                        owner,
                        "unresolved indirect call",
                    );
                }
                Operation::Call { target } => {
                    let callee = self.function(target);
                    effect.add_assign(&callee);
                }
                Operation::Loop {
                    iterations,
                    operations,
                } => {
                    let body = self.operations(owner, operations);
                    effect.add_assign(&body.scale(*iterations));
                    if iterations.is_none() {
                        effect.operations_upper_bound = None;
                        self.emit(
                            "ORES-SA104",
                            Severity::Warning,
                            owner,
                            "loop iteration limit is absent",
                        );
                    }
                }
                Operation::ShareMutable {
                    crosses_actor_boundary,
                } => {
                    effect.may_mutate_foreign_actor = *crosses_actor_boundary;
                }
            }
            summary.add_assign(&effect);
        }
        summary
    }
}
pub fn analyze(program: &Program, profile: Profile) -> Report {
    let mut engine = Engine {
        functions: HashMap::new(),
        active: HashSet::new(),
        cache: HashMap::new(),
        diagnostics: Vec::new(),
    };
    if program.schema_version != SCHEMA_VERSION {
        engine.emit(
            "ORES-SA001",
            Severity::Error,
            "<module>",
            "unsupported IR schema version",
        );
    }
    for function in &program.functions {
        if function.name.trim().is_empty()
            || engine.functions.insert(&function.name, function).is_some()
        {
            engine.emit(
                "ORES-SA002",
                Severity::Error,
                &function.name,
                "empty or duplicate function name",
            );
        }
    }
    let mut summaries = BTreeMap::new();
    for function in &program.functions {
        let summary = engine.function(&function.name);
        if summary.may_mutate_foreign_actor {
            engine.emit(
                "ORES-SA200",
                Severity::Error,
                &function.name,
                "mutable data crosses actor isolation boundary",
            );
        }
        if profile != Profile::General {
            let strict = profile == Profile::HardRealtime;
            let severity = if strict {
                Severity::Error
            } else {
                Severity::Warning
            };
            if summary.may_block || summary.may_wait_unbounded {
                engine.emit(
                    "ORES-SA301",
                    severity,
                    &function.name,
                    "blocking operation or unbounded wait",
                );
            }
            if summary.may_use_unsafe_ffi {
                engine.emit(
                    "ORES-SA302",
                    severity,
                    &function.name,
                    "FFI effect has no real-time contract",
                );
            }
            if summary.allocations_upper_bound != Some(0) {
                engine.emit(
                    "ORES-SA303",
                    severity,
                    &function.name,
                    "zero-allocation bound not proven",
                );
            }
            if summary.copies_upper_bound.is_none()
                || summary.operations_upper_bound.is_none()
                || summary.unresolved_control_flow
            {
                engine.emit(
                    "ORES-SA304",
                    severity,
                    &function.name,
                    "bounded copy/work/control-flow proof incomplete",
                );
            }
        }
        summaries.insert(function.name.clone(), summary);
    }
    // Stable output for CI and downstream tooling.
    engine.diagnostics.sort_by(|a, b| {
        (a.function.as_str(), a.code, a.message.as_str()).cmp(&(
            b.function.as_str(),
            b.code,
            b.message.as_str(),
        ))
    });
    Report {
        schema_version: SCHEMA_VERSION,
        diagnostics: engine.diagnostics,
        functions: summaries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(operations: Vec<Operation>) -> Program {
        Program {
            schema_version: 1,
            functions: vec![Function {
                name: "main".into(),
                operations,
            }],
        }
    }
    #[test]
    fn compute_units_propagate_across_calls() {
        let input = r#"{"schema_version":1,"functions":[{"name":"main","operations":[{"kind":"compute","units":2},{"kind":"call","target":"callee"}]},{"name":"callee","operations":[{"kind":"compute","units":3}]}]}"#;
        let program: Program = serde_json::from_str(input).unwrap();
        let report = analyze(&program, Profile::HardRealtime);
        assert!(!report.has_errors(), "{:?}", report.diagnostics);
        assert_eq!(report.functions["main"].operations_upper_bound, Some(6));
    }
    #[test]
    fn unknown_compute_bound_rejected_for_hard_profile() {
        let input = r#"{"schema_version":1,"functions":[{"name":"main","operations":[{"kind":"compute","units":null}]}]}"#;
        let program: Program = serde_json::from_str(input).unwrap();
        assert!(analyze(&program, Profile::HardRealtime).has_errors());
    }
    #[test]
    fn rejects_omitted_effect_list() {
        let input = r#"{"schema_version":1,"functions":[{"name":"main"}]}"#;
        assert!(serde_json::from_str::<Program>(input).is_err());
    }
    #[test]
    fn rejects_unrecognized_effect_data() {
        let input = r#"{"schema_version":1,"functions":[{"name":"main","operations":[{"kind":"copy","bytes":0,"unknown":true}]}]}"#;
        assert!(serde_json::from_str::<Program>(input).is_err());
    }
    #[test]
    fn hard_realtime_works_for_bounded_zero_alloc_loops() {
        let p = sample(vec![Operation::Loop {
            iterations: Some(10),
            operations: vec![Operation::Copy { bytes: Some(4) }],
        }]);
        let report = analyze(&p, Profile::HardRealtime);
        assert!(!report.has_errors(), "{:?}", report.diagnostics);
        assert_eq!(report.functions["main"].copies_upper_bound, Some(40));
    }
    #[test]
    fn unknown_allocation_is_not_assumed_zero() {
        let p = sample(vec![Operation::Allocate { bytes: None }]);
        assert!(analyze(&p, Profile::HardRealtime)
            .diagnostics
            .iter()
            .any(|d| d.code == "ORES-SA303"));
    }
    #[test]
    fn missing_callee_is_rejected() {
        let p = sample(vec![Operation::Call {
            target: "missing".into(),
        }]);
        assert!(analyze(&p, Profile::General).has_errors());
    }
    #[test]
    fn recursion_is_rejected() {
        let p = sample(vec![Operation::Call {
            target: "main".into(),
        }]);
        assert!(analyze(&p, Profile::General)
            .diagnostics
            .iter()
            .any(|d| d.code == "ORES-SA102"));
    }
    #[test]
    fn actor_mutation_is_always_rejected() {
        let p = sample(vec![Operation::ShareMutable {
            crosses_actor_boundary: true,
        }]);
        assert!(analyze(&p, Profile::General)
            .diagnostics
            .iter()
            .any(|d| d.code == "ORES-SA200"));
    }
    #[test]
    fn integer_overflow_never_wraps_analysis_bounds() {
        let p = sample(vec![
            Operation::Copy {
                bytes: Some(u64::MAX),
            },
            Operation::Copy { bytes: Some(1) },
        ]);
        assert_eq!(
            analyze(&p, Profile::HardRealtime).functions["main"].copies_upper_bound,
            None
        );
    }
    #[test]
    fn zero_trip_loop_has_no_effects() {
        let p = sample(vec![Operation::Loop {
            iterations: Some(0),
            operations: vec![Operation::BlockingIo],
        }]);
        assert!(!analyze(&p, Profile::HardRealtime).functions["main"].may_block);
    }
}
