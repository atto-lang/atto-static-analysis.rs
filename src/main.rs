use std::{env, fs, process};
use atto_static_analysis::scan_unsafe;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: atto-lint-preview <file.atto>");
        process::exit(2);
    }
    let path = &args[1];
    let metadata = fs::metadata(path).unwrap_or_else(|err| {
        eprintln!("cannot stat input: {err}");
        process::exit(2);
    });
    if metadata.len() > 1_048_576 {
        eprintln!("input exceeds 1 MiB");
        process::exit(2);
    }
    let content = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!("cannot read UTF-8 input: {err}");
        process::exit(2);
    });
    let findings = scan_unsafe(&content);
    for finding in &findings {
        println!("{}:{}:{}: {}: unsafe token requires review (lexical preview)",
                 path, finding.line, finding.column, finding.code);
    }
    if !findings.is_empty() { process::exit(1); }
}
