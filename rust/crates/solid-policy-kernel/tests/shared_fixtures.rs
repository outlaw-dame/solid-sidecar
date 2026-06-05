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

#[test]
fn rust_kernel_matches_shared_invalid_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures = [
        (
            "authz_request.unsupported_schema.json",
            "authz_decision.unsupported_schema.json",
        ),
        (
            "authz_request.unsupported_method.json",
            "authz_decision.unsupported_method.json",
        ),
        (
            "authz_request.missing_modes.json",
            "authz_decision.missing_modes.json",
        ),
        (
            "authz_request.unsafe_uri.json",
            "authz_decision.unsafe_uri.json",
        ),
    ];

    for (request_fixture, decision_fixture) in fixtures {
        let request: AuthzRequest = read_fixture(request_fixture)?;
        let expected: AuthzDecision = read_fixture(decision_fixture)?;

        let actual = evaluate(&request, &KernelConfig::default());

        assert_eq!(actual, expected, "fixture pair {request_fixture} / {decision_fixture}");
    }

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
