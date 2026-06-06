use serde::Deserialize;
use solid_policy_kernel::{evaluate, AuthzDecision, AuthzRequest, Decision, KernelConfig};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureManifest {
    schema_version: String,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    request: String,
    decision: String,
    valid_request: bool,
}

#[test]
fn rust_kernel_matches_shared_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: FixtureManifest = read_fixture("authz_manifest.json")?;
    validate_manifest(&manifest)?;

    for fixture in manifest.cases {
        let request: AuthzRequest = read_fixture(&fixture.request)?;
        let expected: AuthzDecision = read_fixture(&fixture.decision)?;

        let actual = evaluate(&request, &KernelConfig::default());

        assert_eq!(actual, expected, "fixture case {}", fixture.name);
        if fixture.valid_request {
            assert_eq!(actual.decision, Decision::Abstain, "valid fixture should abstain");
        } else {
            assert_eq!(actual.decision, Decision::Deny, "invalid fixture should deny");
        }
    }

    Ok(())
}

#[test]
fn rust_manifest_covers_authz_fixture_files() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: FixtureManifest = read_fixture("authz_manifest.json")?;
    validate_manifest(&manifest)?;

    let listed_requests = manifest
        .cases
        .iter()
        .map(|fixture| fixture.request.as_str())
        .collect::<HashSet<_>>();
    let listed_decisions = manifest
        .cases
        .iter()
        .map(|fixture| fixture.decision.as_str())
        .collect::<HashSet<_>>();

    for entry in fs::read_dir(fixture_dir())? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("authz_request.") && name.ends_with(".json") {
            assert!(
                listed_requests.contains(name.as_ref()),
                "request fixture {name:?} is not referenced by authz_manifest.json"
            );
        } else if name.starts_with("authz_decision.") && name.ends_with(".json") {
            assert!(
                listed_decisions.contains(name.as_ref()),
                "decision fixture {name:?} is not referenced by authz_manifest.json"
            );
        }
    }

    Ok(())
}

fn validate_manifest(manifest: &FixtureManifest) -> Result<(), String> {
    if manifest.schema_version != "authz.fixture-manifest.v1" {
        return Err(format!(
            "unexpected fixture manifest schema: {}",
            manifest.schema_version
        ));
    }
    if manifest.cases.is_empty() {
        return Err("fixture manifest must not be empty".to_owned());
    }

    let mut names = HashSet::with_capacity(manifest.cases.len());
    let mut requests = HashSet::with_capacity(manifest.cases.len());
    let mut decisions = HashSet::with_capacity(manifest.cases.len());
    for fixture in &manifest.cases {
        if fixture.name.is_empty() || fixture.request.is_empty() || fixture.decision.is_empty() {
            return Err(format!(
                "fixture case must include name, request, and decision: {fixture:?}"
            ));
        }
        if !valid_fixture_name(&fixture.request, "authz_request.") {
            return Err(format!("invalid request fixture filename: {}", fixture.request));
        }
        if !valid_fixture_name(&fixture.decision, "authz_decision.") {
            return Err(format!(
                "invalid decision fixture filename: {}",
                fixture.decision
            ));
        }
        if !names.insert(fixture.name.as_str()) {
            return Err(format!("duplicate fixture manifest case name: {}", fixture.name));
        }
        if !requests.insert(fixture.request.as_str()) {
            return Err(format!(
                "duplicate fixture manifest request file: {}",
                fixture.request
            ));
        }
        if !decisions.insert(fixture.decision.as_str()) {
            return Err(format!(
                "duplicate fixture manifest decision file: {}",
                fixture.decision
            ));
        }
    }

    Ok(())
}

fn valid_fixture_name(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix)
        && name.ends_with(".json")
        && !name.contains('/')
        && !name.contains('\\')
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
    fixture_dir().join(name)
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("contracts")
        .join("fixtures")
}
