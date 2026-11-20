use ores_analysis::{
    analyze,
    cfg::{analyze_cfg, CfgProgram},
    flow::{analyze_flow, FlowProfile, FlowProgram},
    layout::{analyze_layout, LayoutProgram},
    safety::{analyze_safety, SafetyProfile, SafetyProgram},
    shared_facts::SharedFactsV0,
    Profile, Program, MAX_IR_BYTES,
};
use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};

const MAX_LAYOUT_INPUT_BYTES: u64 = 16 * 1024 * 1024;

const MAX_CFG_INPUT_BYTES: u64 = 1_048_576;

fn read_cfg_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let mut data = String::new();
        io::stdin()
            .lock()
            .take(MAX_CFG_INPUT_BYTES + 1)
            .read_to_string(&mut data)?;
        if data.len() as u64 > MAX_CFG_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CFG IR exceeds 1 MiB limit",
            ));
        }
        Ok(data)
    } else {
        if fs::metadata(path)?.len() > MAX_CFG_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CFG IR exceeds 1 MiB limit",
            ));
        }
        fs::read_to_string(path)
    }
}

fn read_bounded_ir(path: &str) -> io::Result<String> {
    let reader: Box<dyn Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(fs::File::open(path)?)
    };
    let mut bounded = reader.take(MAX_IR_BYTES as u64 + 1);
    let mut source = String::new();
    bounded.read_to_string(&mut source)?;
    if source.len() > MAX_IR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effect/safety IR exceeds 8 MiB input budget",
        ));
    }
    Ok(source)
}

fn read_layout_input(path: &str) -> io::Result<String> {
    if path == "-" {
        let stdin = io::stdin();
        let mut limited = stdin.lock().take(MAX_LAYOUT_INPUT_BYTES + 1);
        let mut buffer = String::new();
        limited.read_to_string(&mut buffer)?;
        if buffer.len() as u64 > MAX_LAYOUT_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "layout IR exceeds 16 MiB input limit",
            ));
        }
        Ok(buffer)
    } else {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_LAYOUT_INPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "layout IR exceeds 16 MiB input limit",
            ));
        }
        fs::read_to_string(path)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if let [_, flag, path, mode] = args.as_slice() {
        if flag == "--flow" {
            let profile = match mode.as_str() {
                "general" => FlowProfile::General,
                "soft" => FlowProfile::Soft,
                "hard" => FlowProfile::Hard,
                _ => {
                    eprintln!("invalid flow profile");
                    return ExitCode::from(2);
                }
            };
            let input: Box<dyn Read> = if path == "-" {
                Box::new(io::stdin())
            } else {
                match fs::File::open(path) {
                    Ok(file) => Box::new(file),
                    Err(error) => {
                        eprintln!("cannot read flow IR: {error}");
                        return ExitCode::from(2);
                    }
                }
            };
            let mut data = String::new();
            if let Err(error) = input.take(4 * 1024 * 1024 + 1).read_to_string(&mut data) {
                eprintln!("cannot read flow IR: {error}");
                return ExitCode::from(2);
            }
            if data.len() > 4 * 1024 * 1024 {
                eprintln!("flow IR exceeds 4 MiB limit");
                return ExitCode::from(2);
            }
            let program: FlowProgram = match serde_json::from_str(&data) {
                Ok(program) => program,
                Err(error) => {
                    eprintln!("invalid flow IR: {error}");
                    return ExitCode::from(2);
                }
            };
            let report = analyze_flow(&program, profile);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("cannot serialize flow report: {error}");
                    return ExitCode::from(2);
                }
            }
            return if report.admitted_to_static_gate {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
    }

    // Restricted Java/Graal typed-AST scalar facts: advisory reporting only.
    // Do not treat a self-declared SHA-256 in JSON as trusted compiler proof.
    if let [_, flag, path, mode] = args.as_slice() {
        if flag == "--static-facts" {
            if mode != "general" {
                eprintln!("shared static-facts v0 lacks verified producer/effect provenance; strict profiles are unsupported");
                return ExitCode::from(2);
            }
            let data = match read_cfg_input(path) {
                Ok(data) => data,
                Err(err) => {
                    eprintln!("cannot read shared static facts: {err}");
                    return ExitCode::from(2);
                }
            };
            let facts: SharedFactsV0 = match serde_json::from_str(&data) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("invalid ores-static-facts/v0 JSON: {err}");
                    return ExitCode::from(2);
                }
            };
            let program = match facts.advisory_effect_ir() {
                Ok(program) => program,
                Err(err) => {
                    eprintln!("static-facts scalar admission rejected: {err}");
                    return ExitCode::from(2);
                }
            };
            let report = analyze(&program, Profile::General);
            let failed = report.has_errors();
            let response = serde_json::json!({
                "input_version": "ores-static-facts/v0",
                "unit": facts.unit,
                "advisory_only": true,
                "producer_authenticated": false,
                "work_allocation_copy_bounds": "unverified",
                "report": report
            });
            match serde_json::to_string_pretty(&response) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("cannot serialize shared fact analysis report: {err}");
                    return ExitCode::from(2);
                }
            }
            return if failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    }

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

    if let [_, flag, path, mode] = args.as_slice() {
        if flag == "--cfg" {
            let profile = match mode.as_str() {
                "general" => SafetyProfile::General,
                "soft" => SafetyProfile::Soft,
                "hard" => SafetyProfile::Hard,
                _ => {
                    eprintln!("invalid CFG profile '{}'", mode);
                    return ExitCode::from(2);
                }
            };
            let data = match read_cfg_input(path) {
                Ok(data) => data,
                Err(err) => {
                    eprintln!("cannot read CFG IR: {err}");
                    return ExitCode::from(2);
                }
            };
            let program: CfgProgram = match serde_json::from_str(&data) {
                Ok(program) => program,
                Err(err) => {
                    eprintln!("invalid CFG-v2 IR: {err}");
                    return ExitCode::from(2);
                }
            };
            let report = analyze_cfg(&program, profile);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(err) => {
                    eprintln!("cannot serialize CFG-v2 report: {err}");
                    return ExitCode::from(2);
                }
            }
            return if report.admitted_to_static_gate {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
    }

    let (safety, path, profile_name) = match args.as_slice() {
        [_, path, profile] => (false, path.as_str(), profile.as_str()),
        [_, flag, path, profile] if flag == "--safety" => (true, path.as_str(), profile.as_str()),
        _ => {
            eprintln!(
                "usage: ores-analyze [--safety|--cfg] <input.json|-> <general|soft|hard> | --static-facts <input.json|-> general | --layout <input.json|->"
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
    let data = match read_bounded_ir(path) {
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
