use ores_analysis::layout::{analyze_layout, LayoutProgram};

#[test]
fn rust_compiler_scalar_layout_fixture_is_accepted_unchanged() {
    let input = include_str!("../../../examples/layout-from-rust-compiler.json");
    let program: LayoutProgram = serde_json::from_str(input).unwrap();
    let report = analyze_layout(&program);
    assert!(!report.has_errors(), "{:?}", report.errors);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(report.regions.is_empty());
}
