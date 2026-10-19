use ores_analysis::{analyze, Profile, Program};
use std::{
    env, fs,
    io::{self, Read},
    process::ExitCode,
};
fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: ores-analyze <input.json|-> <general|soft|hard>");
        return ExitCode::from(2);
    }
    let profile = match args[2].as_str() {
        "general" => Profile::General,
        "soft" => Profile::SoftRealtime,
        "hard" => Profile::HardRealtime,
        _ => {
            eprintln!("unknown profile: {}", args[2]);
            return ExitCode::from(2);
        }
    };
    let input = if args[1] == "-" {
        let mut buffer = String::new();
        match io::stdin().read_to_string(&mut buffer) {
            Ok(_) => Ok(buffer),
            Err(err) => Err(err),
        }
    } else {
        fs::read_to_string(&args[1])
    };
    let program: Program = match input {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(program) => program,
            Err(error) => {
                eprintln!("invalid effect IR: {error}");
                return ExitCode::from(2);
            }
        },
        Err(error) => {
            eprintln!("cannot read input: {error}");
            return ExitCode::from(2);
        }
    };
    let report = analyze(&program, profile);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("serialization failed: {error}");
            return ExitCode::from(2);
        }
    }
    if report.has_errors() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
