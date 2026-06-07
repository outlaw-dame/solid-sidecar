use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySemanticsManifest {
    schema_version: String,
    cases: Vec<PolicySemanticsCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySemanticsCase {
    name: String,
    family: String,
    description: Option<String>,
    request: serde_json::Value,
    policy_documents: Option<Vec<serde_json::Value>>,
    expected_decision: String,
    expected_reason_code: String,
    expected_modes: Option<Vec<String>>,
}

#[test]
fn rust_policy_semantics_manifest_shape_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: PolicySemanticsManifest = read_fixture("policy_semantics_manifest.json")?;
    validate_policy_semantics_manifest(&manifest)?;
    Ok(())
}

fn validate_policy_semantics_manifest(manifest: &PolicySemanticsManifest) -> Result<(), String> {
    if manifest.schema_version != "policy.semantics.fixtures.v1" {
        return Err(format!("unexpected policy semantics schema: {}", manifest.schema_version));
    }
    if manifest.cases.is_empty() {
        return Err("policy semantics manifest must not be empty".to_owned());
    }

    let mut names = HashSet::with_capacity(manifest.cases.len());
    let mut families = HashSet::new();
    for fixture in &manifest.cases {
        if fixture.name.is_empty() {
            return Err("policy semantics case name is required".to_owned());
        }
        if !matches!(fixture.family.as_str(), "wac" | "acp" | "sai") {
            return Err(format!("invalid policy semantics family: {}", fixture.family));
        }
        if !expected_reason_matches_decision(&fixture.expected_decision, &fixture.expected_reason_code) {
            return Err(format!(
                "expected reason {} does not match decision {}",
                fixture.expected_reason_code, fixture.expected_decision
            ));
        }
        if fixture.request.is_null() {
            return Err(format!("case {} has null request", fixture.name));
        }
        if fixture.policy_documents.as_ref().map_or(false, Vec::is_empty) {
            return Err(format!("case {} has empty policy document list", fixture.name));
        }
        if fixture.expected_modes.as_ref().map_or(false, |modes| {
            modes.iter().any(|mode| !matches!(mode.as_str(), "read" | "append" | "write" | "control"))
        }) {
            return Err(format!("case {} has invalid expected mode", fixture.name));
        }
        if fixture.description.as_ref().map_or(false, |description| description.chars().any(char::is_control)) {
            return Err(format!("case {} has control character description", fixture.name));
        }
        if !names.insert(format!("{}:{}", fixture.family, fixture.name)) {
            return Err(format!("duplicate policy semantics case: {}", fixture.name));
        }
        families.insert(fixture.family.as_str());
    }

    for family in ["wac", "acp", "sai"] {
        if !families.contains(family) {
            return Err(format!("missing policy semantics family: {family}"));
        }
    }
    Ok(())
}

fn expected_reason_matches_decision(decision: &str, reason: &str) -> bool {
    match decision {
        "allow" => reason == "policy_allow",
        "deny" => reason == "policy_deny",
        "abstain" => matches!(reason, "kernel_abstain_shadow_mode" | "policy_not_loaded"),
        _ => false,
    }
}

fn read_fixture<T>(name: &str) -> Result<T, Box<dyn std::error::Error>>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(fixture_dir().join(name))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("contracts")
        .join("fixtures")
}
