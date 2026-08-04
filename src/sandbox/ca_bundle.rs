//! Build the merged CA bundle that sandboxed tools trust.
//!
//! The proxy MITMs HTTPS with a per-session CA (CA2 in
//! `docs/SSL_DESIGN.md` terms), and the sandbox must trust that CA for
//! the proxy's leaf certs to verify. Rather than touching the host
//! trust store, we build a **merged bundle** — the system CA bundle the
//! redoubtful process sees (found via `openssl-probe`, honoring
//! `SSL_CERT_FILE` / `SSL_CERT_DIR`), with the proxy's own CA appended —
//! and bind-mount it read-only into the sandbox.
//!
//! In test mode, `SSL_CERT_FILE` points at the test CA1, so
//! [`find_system_ca_bundle`] reads CA1 as the "system" bundle; the
//! merged bundle is then CA1 + CA2, and sandboxed curl can verify both
//! the CA1-issued test upstream (passthrough) and CA2-signed proxy
//! leaves (MITM). In production the "system" part is the real public
//! trust store, so public HTTPS keeps verifying.

use crate::prelude::*;

/// Find the system CA bundle PEM that the redoubtful process sees.
///
/// Uses `openssl_probe::probe()` (honoring `SSL_CERT_FILE` /
/// `SSL_CERT_DIR`), the same discovery `rustls_native_certs` uses for
/// the proxy's upstream connector — so the sandbox leg and the
/// upstream-client leg agree on which roots are "the system".
///
/// Only the single-file form (`cert_file`) is supported: a `cert_dir`
/// of hashed certs with no bundle file is rare, and merging one would
/// mean re-implementing hash-name dedup. If no single bundle file is
/// found we fail loudly — a merged bundle that silently contained only
/// our own CA would break public HTTPS.
pub fn find_system_ca_bundle() -> Result<Vec<u8>> {
    let probe = openssl_probe::probe();
    debug!(
        cert_file = ?probe.cert_file,
        cert_dir = ?probe.cert_dir,
        "discovering system CA bundle"
    );
    let path = probe.cert_file.ok_or_else(Error::no_root_certificates)?;
    std::fs::read(&path).map_err(|e| Error::could_not_read_file(path, e))
}

/// Build the merged sandbox CA bundle: the system bundle followed by
/// our own CA PEM.
///
/// Both inputs are raw PEM bytes. We ensure a newline separates them so
/// a bundle that ends without a trailing newline still concatenates
/// cleanly.
pub fn build_sandbox_ca_bundle(system: &[u8], our_ca: &[u8]) -> Vec<u8> {
    // The capacity is a performance hint only: a clamped (saturating)
    // value is harmless because `extend_from_slice` reallocates as
    // needed, so the exact arithmetic doesn't need checked overflow.
    let mut merged = Vec::with_capacity(
        system.len().saturating_add(our_ca.len()).saturating_add(1),
    );
    merged.extend_from_slice(system);
    if !merged.ends_with(b"\n") {
        merged.push(b'\n');
    }
    merged.extend_from_slice(our_ca);
    if !merged.ends_with(b"\n") {
        merged.push(b'\n');
    }
    merged
}

/// The path inside the sandbox where the merged CA bundle is
/// bind-mounted. It lives under `/tmp` (a fresh per-sandbox tmpfs) so
/// bwrap can create the destination — the baseline's `/etc` ro-bind
/// blocks new files under it. Sandboxed tools read it via the `*_CA_*`
/// env vars, so the exact location is arbitrary.
pub const CA_BUNDLE_SANDBOX_PATH: &str = "/tmp/redoubtful-ca-bundle.crt";

/// Build a host-side [`NamedTempFile`] containing the merged sandbox
/// bundle (system + our CA), so `proxy_profile` can bind-mount it.
///
/// The file is auto-cleaned when the returned handle drops.
pub fn write_sandbox_ca_bundle(
    system: &[u8],
    our_ca: &[u8],
) -> Result<tempfile::NamedTempFile> {
    let bundle = build_sandbox_ca_bundle(system, our_ca);
    let file = tempfile::NamedTempFile::new()
        .map_err(|e| Error::other("could not create CA bundle temp file", e))?;
    std::fs::write(file.path(), &bundle).map_err(|e| {
        Error::other("could not write CA bundle to temp file", e)
    })?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn build_sandbox_ca_bundle_concatenates_system_then_our_ca() {
        let system =
            b"-----BEGIN CERTIFICATE-----\nSYS\n-----END CERTIFICATE-----\n";
        let our =
            b"-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----\n";
        let merged = build_sandbox_ca_bundle(system, our);
        let mut expected = Vec::new();
        expected.extend_from_slice(system);
        expected.extend_from_slice(our);
        assert_eq!(merged, expected);
    }

    #[test]
    fn build_sandbox_ca_bundle_inserts_newline_separator() {
        // If the system bundle lacks a trailing newline, we insert one
        // so the two PEM blocks never merge into one line.
        let system = b"sys-no-newline";
        let our = b"-----BEGIN CERTIFICATE-----\nCA2\n";
        let merged = build_sandbox_ca_bundle(system, our);
        assert_eq!(
            String::from_utf8_lossy(&merged),
            "sys-no-newline\n-----BEGIN CERTIFICATE-----\nCA2\n",
        );
    }

    #[test]
    fn write_sandbox_ca_bundle_persists_merged_bytes() {
        let system = b"sys-pem\n";
        let our = b"our-ca-pem\n";
        let file = write_sandbox_ca_bundle(system, our).expect("writes");
        let on_disk = std::fs::read(file.path()).expect("reads back");
        assert_eq!(on_disk, b"sys-pem\nour-ca-pem\n");
        // The NamedTempFile is cleaned on drop.
    }

    #[test]
    fn sandbox_path_is_under_tmp() {
        // The bundle is bound into `/tmp` (a fresh per-sandbox tmpfs)
        // specifically because the baseline `/etc` ro-bind blocks
        // creating new destination files there.
        assert!(
            Path::new(CA_BUNDLE_SANDBOX_PATH).starts_with(Path::new("/tmp")),
            "CA bundle sandbox path must live under /tmp"
        );
    }
}
