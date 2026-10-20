use ores_analysis::{analyze, safety::{analyze_safety, SafetyProfile, SafetyProgram}, flow::{analyze_flow, FlowProfile, FlowProgram}, Profile, Program};
use std::{env, fs, io::{self, Read}, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (mode, path, profile_name) = match args.as_slice() {
        [_, path, profile] => ("effects", path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--safety" || flag == "--flow" => (flag.as_str(), path.as_str(), profile.as_str()),
        _ => {
            eprintln!("usage: ores-analyze [--safety|--flow] <input.json|-> <general|soft|hard>");
            return ExitCode::from(2);
        }
    };
    let profile = match profile_name {
        "general" => Profile::General,
        "soft" => Profile::SoftRealtime,
        "hard" => Profile::HardRealtime,
        _ => {
            eprintln!("invalid profile '{profile_name}'");
            return ExitCode::from(2);
        }
    };
    let input = if path == "-" {
        let mut buffer = String::new();
        match io::stdin().read_to_string(&mut buffer) {
            Ok(_) => Ok(buffer),
            Err(err) => Err(err),
        }
    } else {
        fs::read_to_string(path)
    };
    let data = match input {
        Ok(value) => value,
        Err(err) => {
            eprintln!("cannot read input: {err}");
            return ExitCode::from(2);
        }
    };
    if mode == "--flow" {
        let program: FlowProgram = match serde_json::from_str(&data) {
            Ok(value) => value,
            Err(err) => { eprintln!("invalid CFG MIR envelope: {err}"); return ExitCode::from(2); }
        };
        let profile = match profile {
            Profile::General => FlowProfile::General,
            Profile::SoftRealtime => FlowProfile::Soft,
            Profile::HardRealtime => FlowProfile::Hard,
        };
        let result = analyze_flow(&program, profile);
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(err) => { eprintln!("cannot serialize report: {err}"); return ExitCode::from(2); }
        }
        if result.admitted_to_static_gate { ExitCode::SUCCESS } else { ExitCode::from(1) }
    } else if mode == "--safety" {
        let program: SafetyProgram = match serde_json::from_str(&data) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("invalid MIR safety envelope: {err}");
                return ExitCode::from(2);
            }
        };
        let mode = match profile {
            Profile::General => SafetyProfile::General,
            Profile::SoftRealtime => SafetyProfile::Soft,
            Profile::HardRealtime => SafetyProfile::Hard,
        };
        let result = analyze_safety(&program, mode);
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("cannot serialize report: {err}");
                return ExitCode::from(2);
            }
        }
        if result.admitted_to_static_gate { ExitCode::SUCCESS } else { ExitCode::from(1) }
    } else {
        let program: Program = match serde_json::from_str(&data) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("invalid effect IR: {err}");
                return ExitCode::from(2);
            }
        };
        let result = analyze(&program, profile);
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("cannot serialize report: {err}");
                return ExitCode::from(2);
            }
        }
        if result.has_errors() { ExitCode::from(1) } else { ExitCode::SUCCESS }
    }
}
