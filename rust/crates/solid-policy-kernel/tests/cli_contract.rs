use solid_policy_kernel::AuthzDecision;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[test]
fn cli_evaluates_shared_fixture_file() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_solid-policy-kernel-eval"))
        .arg(fixture_path("authz_request.valid.json"))
        .output()?;

    assert!(
        output.status.success(),
        "expected CLI success; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "expected no stderr; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let actual = serde_json::from_slice::<AuthzDecision>(&output.stdout)?;
    let expected = read_fixture::<AuthzDecision>("authz_decision.shadow.json")?;
    assert_eq!(actual, expected);

    Ok(())
}

#[test]
fn cli_rejects_malformed_stdin_json() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_solid-policy-kernel-eval"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(b"{not-json")?;
    } else {
        return Err("failed to open child stdin".into());
    }

    let output = child.wait_with_output()?;
    assert!(!output.status.success(), "expected CLI failure");
    assert!(
        output.stdout.is_empty(),
        "expected no stdout on decode failure; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to decode authz request JSON"),
        "unexpected stderr: {stderr}"
    );

    Ok(())
}

fn read_fixture<T>(name: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(fixture_path(name))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("contracts")
        .join("fixtures")
        .join(name)
}
