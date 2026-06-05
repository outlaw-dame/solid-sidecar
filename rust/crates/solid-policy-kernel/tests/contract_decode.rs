use solid_policy_kernel::{AuthzDecision, AuthzRequest};

#[test]
fn request_decode_rejects_unknown_fields() {
    let input = r#"{
        "schema_version": "authz.v1",
        "request_id": "req-1",
        "method": "GET",
        "resource_uri": "https://pod.example/card",
        "requested_modes": ["read"],
        "now_unix": 1700000000,
        "extra": true
    }"#;

    let result = serde_json::from_str::<AuthzRequest>(input);
    assert!(result.is_err());
}

#[test]
fn decision_decode_rejects_unknown_fields() {
    let input = r#"{
        "schema_version": "authz.v1",
        "request_id": "req-1",
        "decision": "abstain",
        "reason_code": "kernel_abstain_shadow_mode",
        "cache_ttl_seconds": 0,
        "audit": {
            "request_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "policy_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "extra": true
    }"#;

    let result = serde_json::from_str::<AuthzDecision>(input);
    assert!(result.is_err());
}
