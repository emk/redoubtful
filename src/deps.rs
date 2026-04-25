//! Probes for the external binaries `redoubtful` requires at runtime.
//!
//! `bwrap` (bubblewrap) provides the mount/pid/user/ipc/uts/cgroup
//! namespaces; `pasta` (passt) provides rootless networking. We probe both
//! once at startup so the user gets a clear error naming the missing
//! package, rather than a confusing failure deep inside the launcher.

use std::io;

use tokio::process::Command;

use crate::prelude::*;

/// Versions of the external binaries `redoubtful` depends on.
pub struct DependencyVersions {
    /// First non-empty line of `bwrap --version` (e.g. `"bubblewrap 0.9.0"`).
    pub bwrap: String,
    /// First non-empty line of `pasta --version`.
    pub pasta: String,
}

/// Probe `bwrap` and `pasta`, returning their reported versions or a
/// diagnostic naming the missing binary and its package.
#[instrument(level = "debug", skip_all)]
pub async fn probe_required() -> Result<DependencyVersions> {
    let bwrap = probe("bwrap", "bubblewrap").await?;
    let pasta = probe("pasta", "passt").await?;
    Ok(DependencyVersions { bwrap, pasta })
}

/// Run `<binary> --version` and return the first non-empty line of stdout.
/// Returns a friendly diagnostic if the binary is not on `$PATH`.
#[instrument(level = "debug", skip_all, fields(binary))]
async fn probe(binary: &str, package: &str) -> Result<String> {
    let output = match Command::new(binary).arg("--version").output().await {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Error::missing_dependency(binary, package));
        }
        Err(e) => return Err(Error::could_not_run(binary, e)),
    };

    if !output.status.success() {
        return Err(Error::could_not_get_version(binary));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| Error::could_not_get_version(binary))?
        .to_string();
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_binary_names_the_package() {
        let err =
            probe("redoubtful-definitely-not-a-real-binary-xyz", "phantom-pkg")
                .await
                .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("redoubtful-definitely-not-a-real-binary-xyz"),
            "{msg}"
        );
        assert!(msg.contains("phantom-pkg"), "{msg}");
    }
}
