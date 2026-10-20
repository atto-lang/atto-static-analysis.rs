use ores_analysis::{
    analyze,
    layout::{analyze_layout, LayoutProgram},
    safety::{analyze_safety, SafetyProfile, SafetyProgram},
    Profile, Program,
};
use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};

const MAX_LAYOUT_INPUT_BYTES: u64 = 16 * 1024 * 1024;

const MAX_ANALYSIS_INPUT_BYTES: u64 = 8 * 1024 * 1024;

fn read_bounded(path: &str, limit: u64) -> io::Result<String> {
    // Bound *actual* reads, not just metadata (files may grow or be FIFOs).
    // A single extra byte distinguishes an oversized stream from a valid one.
    let mut buffer = String::new();
    if path == "-" {
        io::stdin().lock().take(limit + 1).read_to_string(&mut buffer)?;
    } else {
        fs::File::open(path)?.take(limit + 1).read_to_string(&mut buffer)?;
    }
    if buffer.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("analysis input exceeds {limit} bytes"),
        ));
    }
    Ok(buffer)
}

fn read_input(path: &str) -> io::Result<String> {
    read_bounded(path, MAX_ANALYSIS_INPUT_BYTES)
}

fn read_layout_input(path: &str) -> io::Result<String> {
    read_bounded(path, MAX_LAYOUT_INPUT_BYTES)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if let [_, flag, path] = args.as_slice() {
        if flag == "--layout" {
            let data = match read_layout_input(path) {
                Ok(data) => data,
                Err(err) => {
                    eprintln!("cannot read input: {err}");
                    return ExitCode::from(2);
                }
            };
            let program: LayoutProgram = match serde_json::from_str(&data) {
                Ok(program) => program,
                Err(err) => {
                    eprintln!("invalid layout IR: {err}");
                    return ExitCode::from(2);
                }
            };
            let report = analyze_layout(&program);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("cannot serialize layout report: {err}");
                    return ExitCode::from(2);
                }
            }
            return if report.has_errors() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    }

    let (safety, path, profile_name) = match args.as_slice() {
        [_, path, profile] => (false, path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--safety" => (true, path.as_str(), profile.as_str()),
        _ => {
            eprintln!(
                "usage: ores-analyze [--safety] <input.json|-> <general|soft|hard> | --layout <input.json|->"
            );
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
    let data = match read_input(path) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("cannot read input: {err}");
            return ExitCode::from(2);
        }
    };

    if safety {
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
        if result.admitted_to_static_gate {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
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
        if result.has_errors() {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    }
}
