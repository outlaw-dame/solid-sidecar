use solid_policy_kernel::{
    evaluate, AccessMode, AuthzRequest, Decision, KernelConfig, PolicyDocument, ReasonCode,
    SCHEMA_VERSION,
};
use std::collections::BTreeMap;

#[test]
fn valid_request_abstains_in_shadow_mode() {
    let request = sample_request();
    let decision = evaluate(&request, &KernelConfig::default());

    assert_eq!(decision.schema_version, SCHEMA_VERSION);
    assert_eq!(decision.request_id, "req-1");
    assert_eq!(decision.decision, Decision::Abstain);
    assert_eq!(decision.reason_code, ReasonCode::KernelAbstainShadowMode);
    assert_eq!(decision.status_hint, None);
    assert_eq!(decision.cache_ttl_seconds, 0);
    assert_eq!(decision.audit.request_hash.len(), 64);
    assert_eq!(decision.audit.policy_hash.len(), 64);
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let mut request = sample_request();
    request.schema_version = "authz.v0".to_owned();
    let decision = evaluate(&request, &KernelConfig::default());

    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, ReasonCode::UnsupportedSchemaVersion);
    assert_eq!(decision.status_hint, Some(400));
}

#[test]
fn missing_modes_are_rejected() {
    let mut request = sample_request();
    request.requested_modes.clear();
    let decision = evaluate(&request, &KernelConfig::default());

    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, ReasonCode::MissingRequestedModes);
    assert_eq!(decision.status_hint, Some(400));
}

#[test]
fn unsafe_resource_uris_are_rejected() {
    let mut request = sample_request();
    request.resource_uri = "ftp://pod.example/alice/card".to_owned();
    let decision = evaluate(&request, &KernelConfig::default());

    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, ReasonCode::UnsafeResourceUri);
    assert_eq!(decision.status_hint, Some(400));
}

#[test]
fn equivalent_policy_documents_hash_deterministically() {
    let mut left = sample_request();
    let mut right = sample_request();
    right.policy_documents.reverse();

    let left_decision = evaluate(&left, &KernelConfig::default());
    let right_decision = evaluate(&right, &KernelConfig::default());

    assert_eq!(left_decision.audit.policy_hash, right_decision.audit.policy_hash);

    left.resource_metadata.insert("z".to_owned(), "1".to_owned());
    right.resource_metadata.insert("z".to_owned(), "1".to_owned());
    let left_decision = evaluate(&left, &KernelConfig::default());
    let right_decision = evaluate(&right, &KernelConfig::default());
    assert_eq!(left_decision.audit.request_hash, right_decision.audit.request_hash);
}

#[test]
fn decision_serializes_with_contract_names() -> Result<(), Box<dyn std::error::Error>> {
    let decision = evaluate(&sample_request(), &KernelConfig::default());
    let encoded = serde_json::to_string(&decision)?;

    assert!(encoded.contains("kernel_abstain_shadow_mode"));
    assert!(encoded.contains("abstain"));
    Ok(())
}

fn sample_request() -> AuthzRequest {
    let mut resource_metadata = BTreeMap::new();
    resource_metadata.insert("container".to_owned(), "false".to_owned());

    AuthzRequest {
        schema_version: SCHEMA_VERSION.to_owned(),
        request_id: "req-1".to_owned(),
        method: "GET".to_owned(),
        resource_uri: "https://pod.example/alice/card".to_owned(),
        agent_webid: Some("https://alice.example/profile#me".to_owned()),
        client_id: Some("https://app.example/id".to_owned()),
        issuer: Some("https://issuer.example".to_owned()),
        origin: Some("https://app.example".to_owned()),
        requested_modes: vec![AccessMode::Read],
        resource_version: Some("resource-v1".to_owned()),
        policy_version: Some("policy-v1".to_owned()),
        resource_metadata,
        policy_documents: vec![
            PolicyDocument {
                uri: "https://pod.example/.acl".to_owned(),
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                content_type: "text/turtle".to_owned(),
            },
            PolicyDocument {
                uri: "https://pod.example/settings/policies".to_owned(),
                sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                content_type: "text/turtle".to_owned(),
            },
        ],
        now_unix: 1_700_000_000,
    }
}
