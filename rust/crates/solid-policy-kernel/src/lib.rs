#![forbid(unsafe_code)]

pub mod kernel;
pub mod types;

pub use kernel::{evaluate, KernelConfig};
pub use types::{
    AccessMode, AuditFields, AuthzDecision, AuthzRequest, Decision, PolicyDocument, ReasonCode,
    SCHEMA_VERSION,
};
