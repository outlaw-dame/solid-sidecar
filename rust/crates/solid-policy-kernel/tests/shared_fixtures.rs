use serde::Deserialize;
use solid_policy_kernel::{evaluate, AuthzDecision, AuthzRequest, KernelConfig};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    schema_version: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct FixtureCase {
    name: String,
    request: String,
    decision: String,
}

#[test]
fn rust_kernel_matches_shared_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: FixtureManifest = read_fixture("authz_manifest.json")?;
    assert_eq!(manifest.schema_version, "authz.fixture-manifest.v1");
    assert!(!manifest.cases.is_empty(), "fixture manifest must not be empty");

    for fixture in manifest.cases {
        let request: AuthzRequest = read_fixture(&fixture.request)?;
        let expected: AuthzDecision = read_fixture(&fixture.decision)?;

        let actual = evaluate(&request, &KernelConfig::default());

        assert_eq!(actual, expected, "fixture case {}", fixture.name);
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
