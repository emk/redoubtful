//! JSON data structures representing `show` output.

// We don't need struct field docs in test code.
#![allow(missing_docs)]

use std::path::PathBuf;

/// Minimal struct mirroring `mounts::Mount` for deserialization.
/// Defined here (not imported) because integration tests don't share
/// crate-internal types — and the test should fail loudly if the
/// per-mount JSON shape changes unexpectedly.
#[derive(serde::Deserialize)]
pub struct MountJson {
    pub sandbox: PathBuf,
    // Other fields ignored — we only need `sandbox` for the
    // unexpected-paths assertion below.
}

/// Top-level shape of `redoubtful show --json`. Fields are split out
/// per inventory so each test can grab just what it needs.
#[derive(serde::Deserialize)]
pub struct ShowJson {
    pub mounts: Vec<MountJson>,
    pub forwards: Vec<ForwardJson>,
    pub env: Vec<EnvJson>,
}

/// Minimal struct mirroring `forward::Forward` for deserialization.
#[derive(serde::Deserialize)]
pub struct ForwardJson {
    pub host_port: u16,
    pub sandbox_port: u16,
}

/// Minimal struct mirroring `env::EnvEntry` for deserialization. Each
/// entry is a fully-resolved `name=value` pair; `show --json`
/// describes exactly the env the sandbox would see at that instant
/// (passthroughs are already materialized, unset ones are absent).
#[derive(serde::Deserialize)]
pub struct EnvJson {
    pub name: String,
    pub value: String,
}
