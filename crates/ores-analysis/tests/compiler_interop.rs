//! Interoperability contract: compiler `oresc --effects tests/fixtures/forward.ores`
//! must remain compatible with the independent analyzer.
use ores_analysis::{analyze, Profile, Program};

#[test]
fn accepts_rust_compiler_forward_call_fixture() {
    let input = include_str!("../../../fixtures/rust-forward.effects.json");
    let program: Program = serde_json::from_str(input).expect("v1 compiler JSON");
    let report = analyze(&program, Profile::HardRealtime);
    assert!(!report.has_errors(), "{:?}", report.diagnostics);
    assert_eq!(report.functions["main"].operations_upper_bound, Some(6));
    assert_eq!(report.functions["times"].operations_upper_bound, Some(3));
    assert_eq!(report.functions["main"].allocations_upper_bound, Some(0));
}

#[test]
fn rejects_removed_callee_in_compiler_fixture() {
    let input = include_str!("../../../fixtures/rust-forward.effects.json");
    let mut program: Program = serde_json::from_str(input).unwrap();
    program.functions.retain(|f| f.name != "times");
    assert!(analyze(&program, Profile::General).has_errors());
}
