use ores_analysis::{
    analyze,
    safety::{analyze_safety, SafetyProfile, SafetyProgram},
    Profile, Program, MAX_IR_BYTES,
};
use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};
fn read_ir(path: &str) -> io::Result<String> {
    let reader: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    };
    let mut bounded = reader.take(MAX_IR_BYTES as u64 + 1);
    let mut input = String::new();
    bounded.read_to_string(&mut input)?;
    if input.len() > MAX_IR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effect IR exceeds 8 MiB limit",
        ));
    }
    Ok(input)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let (safety, path, profile_name) = match args.as_slice() {
        [_, path, profile] => (false, path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--safety" => (true, path.as_str(), profile.as_str()),
        _ => {
            eprintln!("usage: ores-analyze [--safety] <input.json|-> <general|soft|hard>");
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
    let input = read_ir(path);
    let data = match input {
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
