use solid_policy_kernel::{evaluate, AuthzDecision, AuthzRequest, KernelConfig};
use std::fs;
use std::path::PathBuf;

#[test]
fn rust_kernel_matches_shared_shadow_fixture() -> Result<(), Box<dyn std::error::Error>> {
    let request: AuthzRequest = read_fixture("authz_request.valid.json")?;
    let expected: AuthzDecision = read_fixture("authz_decision.shadow.json")?;

    let actual = evaluate(&request, &KernelConfig::default());

    assert_eq!(actual, expected);
    Ok(())
}

fn read_fixture<T>(name: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let path = fixture_path(name);
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("contracts")
        .join("fixtures")
        .join(name)
}
