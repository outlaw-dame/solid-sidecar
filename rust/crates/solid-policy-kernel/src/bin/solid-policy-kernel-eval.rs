use solid_policy_kernel::{evaluate, AuthzRequest, KernelConfig};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "solid-policy-kernel-eval: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [] => evaluate_stdin(),
        [arg] if arg == "-h" || arg == "--help" => {
            print_usage();
            Ok(())
        }
        [path] => evaluate_file(path),
        _ => Err("usage: solid-policy-kernel-eval [REQUEST_JSON_FILE]".to_owned()),
    }
}

fn evaluate_stdin() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read request from stdin: {error}"))?;
    evaluate_json(&input)
}

fn evaluate_file(path: &str) -> Result<(), String> {
    let input = fs::read_to_string(path)
        .map_err(|error| format!("failed to read request file {path:?}: {error}"))?;
    evaluate_json(&input)
}

fn evaluate_json(input: &str) -> Result<(), String> {
    let request = serde_json::from_str::<AuthzRequest>(input)
        .map_err(|error| format!("failed to decode authz request JSON: {error}"))?;
    let decision = evaluate(&request, &KernelConfig::default());
    serde_json::to_writer_pretty(io::stdout(), &decision)
        .map_err(|error| format!("failed to encode authz decision JSON: {error}"))?;
    writeln!(io::stdout()).map_err(|error| format!("failed to flush stdout: {error}"))?;
    Ok(())
}

fn print_usage() {
    println!("usage: solid-policy-kernel-eval [REQUEST_JSON_FILE]");
    println!();
    println!("Reads an authz.v1 request JSON document from a file or stdin and writes the deterministic shadow decision JSON to stdout.");
}
