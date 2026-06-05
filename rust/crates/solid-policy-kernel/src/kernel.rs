use crate::types::{
    AccessMode, AuditFields, AuthzDecision, AuthzRequest, Decision, PolicyDocument, ReasonCode,
    SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelConfig {
    pub shadow_mode: bool,
    pub max_request_id_len: usize,
    pub max_resource_uri_len: usize,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            shadow_mode: true,
            max_request_id_len: 128,
            max_resource_uri_len: 4096,
        }
    }
}

pub fn evaluate(request: &AuthzRequest, config: &KernelConfig) -> AuthzDecision {
    let audit = audit_fields(request);

    if request.schema_version != SCHEMA_VERSION {
        return decision(
            request,
            audit,
            Decision::Deny,
            ReasonCode::UnsupportedSchemaVersion,
            Some(400),
            0,
            config,
        );
    }

    if !is_valid_request_id(&request.request_id, config.max_request_id_len)
        || !is_supported_method(&request.method)
    {
        return decision(
            request,
            audit,
            Decision::Deny,
            ReasonCode::InvalidRequest,
            Some(400),
            0,
            config,
        );
    }

    if request.requested_modes.is_empty() {
        return decision(
            request,
            audit,
            Decision::Deny,
            ReasonCode::MissingRequestedModes,
            Some(400),
            0,
            config,
        );
    }

    if !is_safe_resource_uri(&request.resource_uri, config.max_resource_uri_len) {
        return decision(
            request,
            audit,
            Decision::Deny,
            ReasonCode::UnsafeResourceUri,
            Some(400),
            0,
            config,
        );
    }

    if config.shadow_mode {
        return decision(
            request,
            audit,
            Decision::Abstain,
            ReasonCode::KernelAbstainShadowMode,
            None,
            0,
            config,
        );
    }

    decision(
        request,
        audit,
        Decision::Abstain,
        ReasonCode::PolicyNotLoaded,
        None,
        0,
        config,
    )
}

fn decision(
    request: &AuthzRequest,
    audit: AuditFields,
    decision: Decision,
    reason_code: ReasonCode,
    status_hint: Option<u16>,
    cache_ttl_seconds: u16,
    config: &KernelConfig,
) -> AuthzDecision {
    AuthzDecision {
        schema_version: SCHEMA_VERSION.to_owned(),
        request_id: decision_request_id(request, &audit, config),
        decision,
        reason_code,
        status_hint,
        cache_ttl_seconds,
        policy_version: request.policy_version.clone(),
        resource_version: request.resource_version.clone(),
        audit,
    }
}

fn decision_request_id(
    request: &AuthzRequest,
    audit: &AuditFields,
    config: &KernelConfig,
) -> String {
    if is_valid_request_id(&request.request_id, config.max_request_id_len) {
        return request.request_id.clone();
    }
    let prefix_len = audit.request_hash.len().min(32);
    format!("invalid-request-{}", &audit.request_hash[..prefix_len])
}

fn is_valid_request_id(request_id: &str, max_len: usize) -> bool {
    !request_id.is_empty()
        && request_id.len() <= max_len
        && request_id.bytes().all(|byte| byte.is_ascii_graphic())
}

fn is_supported_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

fn is_safe_resource_uri(resource_uri: &str, max_len: usize) -> bool {
    if resource_uri.is_empty() || resource_uri.len() > max_len {
        return false;
    }
    if resource_uri
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return false;
    }
    if resource_uri.contains('#') {
        return false;
    }
    resource_uri.starts_with("https://") || resource_uri.starts_with("http://")
}

fn audit_fields(request: &AuthzRequest) -> AuditFields {
    AuditFields {
        request_hash: sha256_hex(canonical_request(request).as_bytes()),
        policy_hash: sha256_hex(canonical_policy_documents(&request.policy_documents).as_bytes()),
    }
}

fn canonical_request(request: &AuthzRequest) -> String {
    let mut output = String::new();
    push_field(&mut output, "schema_version", &request.schema_version);
    push_field(&mut output, "request_id", &request.request_id);
    push_field(&mut output, "method", &request.method);
    push_field(&mut output, "resource_uri", &request.resource_uri);
    push_option(&mut output, "agent_webid", request.agent_webid.as_deref());
    push_option(&mut output, "client_id", request.client_id.as_deref());
    push_option(&mut output, "issuer", request.issuer.as_deref());
    push_option(&mut output, "origin", request.origin.as_deref());
    push_modes(&mut output, &request.requested_modes);
    push_option(
        &mut output,
        "resource_version",
        request.resource_version.as_deref(),
    );
    push_option(
        &mut output,
        "policy_version",
        request.policy_version.as_deref(),
    );
    for (key, value) in &request.resource_metadata {
        push_field(&mut output, "resource_metadata_key", key);
        push_field(&mut output, "resource_metadata_value", value);
    }
    push_field(&mut output, "now_unix", &request.now_unix.to_string());
    output
}

fn canonical_policy_documents(policy_documents: &[PolicyDocument]) -> String {
    let mut sorted = policy_documents.to_vec();
    sorted.sort_by(|left, right| {
        left.uri
            .cmp(&right.uri)
            .then(left.sha256.cmp(&right.sha256))
            .then(left.content_type.cmp(&right.content_type))
    });

    let mut output = String::new();
    for policy_document in sorted {
        push_field(&mut output, "policy_uri", &policy_document.uri);
        push_field(&mut output, "policy_sha256", &policy_document.sha256);
        push_field(&mut output, "policy_content_type", &policy_document.content_type);
    }
    output
}

fn push_option(output: &mut String, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_field(output, name, value);
    }
}

fn push_modes(output: &mut String, modes: &[AccessMode]) {
    let mut sorted = modes.to_vec();
    sorted.sort();
    for mode in sorted {
        let value = match mode {
            AccessMode::Read => "read",
            AccessMode::Append => "append",
            AccessMode::Write => "write",
            AccessMode::Control => "control",
        };
        push_field(output, "requested_mode", value);
    }
}

fn push_field(output: &mut String, name: &str, value: &str) {
    output.push_str(name);
    output.push('\u{1f}');
    output.push_str(value);
    output.push('\u{1e}');
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{
        decision_request_id, is_safe_resource_uri, is_valid_request_id, AuditFields, AuthzRequest,
        KernelConfig, SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;

    #[test]
    fn request_ids_must_be_visible_ascii() {
        assert!(is_valid_request_id("req-123", 128));
        assert!(!is_valid_request_id("", 128));
        assert!(!is_valid_request_id("bad request", 128));
        assert!(!is_valid_request_id("bad\nrequest", 128));
    }

    #[test]
    fn invalid_request_ids_use_hash_surrogate_for_decisions() {
        let request = AuthzRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            request_id: "bad request".to_owned(),
            method: "GET".to_owned(),
            resource_uri: "https://pod.example/alice/card".to_owned(),
            agent_webid: None,
            client_id: None,
            issuer: None,
            origin: None,
            requested_modes: vec![],
            resource_version: None,
            policy_version: None,
            resource_metadata: BTreeMap::new(),
            policy_documents: vec![],
            now_unix: 0,
        };
        let audit = AuditFields {
            request_hash: "0123456789abcdef0123456789abcdefffffffffffffffffffffffffffffffff".to_owned(),
            policy_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
        };

        assert_eq!(
            decision_request_id(&request, &audit, &KernelConfig::default()),
            "invalid-request-0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn resource_uris_must_be_http_without_fragments_or_backslashes() {
        assert!(is_safe_resource_uri("https://pod.example/alice/card", 4096));
        assert!(!is_safe_resource_uri("ftp://pod.example/alice/card", 4096));
        assert!(!is_safe_resource_uri("https://pod.example/a#frag", 4096));
        assert!(!is_safe_resource_uri("https://pod.example/a\\b", 4096));
    }
}
