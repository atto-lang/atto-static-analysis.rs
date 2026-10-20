use ores_analysis::cfg::{analyze_cfg, CfgProgram};
use ores_analysis::{analyze, safety::{analyze_safety, SafetyProfile, SafetyProgram}, Profile, Program};
use std::{env, fs, io::{self, Read}, process::ExitCode};
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (mode_name, path, profile_name) = match args.as_slice() {
        [_, path, profile] => ("effects", path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--safety" => ("linear", path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--cfg" => ("cfg", path.as_str(), profile.as_str()),
        _ => {
            eprintln!("usage: ores-analyze [--safety|--cfg] <input.json|-> <general|soft|hard>");
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
    if data.len() > 1_048_576 {
        eprintln!("analysis input exceeds 1 MiB resource budget");
        return ExitCode::from(2);
    }
    if mode_name == "cfg" {
        let program: CfgProgram = match serde_json::from_str(&data) {
            Ok(program) => program,
            Err(err) => { eprintln!("invalid CFG IR: {err}"); return ExitCode::from(2); }
        };
        let mode = match profile {
            Profile::General => SafetyProfile::General,
            Profile::SoftRealtime => SafetyProfile::Soft,
            Profile::HardRealtime => SafetyProfile::Hard,
        };
        let result = analyze_cfg(&program, mode);
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(err) => { eprintln!("cannot serialize CFG report: {err}"); return ExitCode::from(2); }
        }
        if result.admitted_to_static_gate { ExitCode::SUCCESS } else { ExitCode::from(1) }
    } else if mode_name == "linear" {
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
