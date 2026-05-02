//! Preflight checks for the host: `bwrap` on `$PATH`, `pasta` on
//! `$PATH`, and the ability to create a user namespace.
//!
//! Same logic backs both `redoubtful check` (always reports) and
//! `redoubtful run` (silent on success, full report on failure). The
//! `userns` check is composite: it reads the AppArmor sysctl first
//! and only execs `bwrap` if the restriction is active. On failure,
//! it emits a Tier 2 AppArmor profile with the running binary's path
//! substituted in, ready to paste into `/etc/apparmor.d/redoubtful`.
//! See `docs/APPARMOR_USERNS.md` for the broader story.

use std::{
    env, fs,
    io::{self, Write},
};

use console::{StyledObject, style};
use tokio::process::Command;

use crate::prelude::*;

/// Wrap `text` in a [`StyledObject`] tied to stderr. The check
/// report is emitted on stderr in both `redoubtful check` and
/// `redoubtful run` (it's diagnostic output, not data anyone
/// would pipe into `jq`), so console's stderr color setting is
/// always the right one to consult. Auto-detection — `NO_COLOR`,
/// `CLICOLOR_FORCE`, `is_terminal` — happens per `StyledObject`
/// at format time, so chained `.bold()` / `.cyan()` calls no-op
/// transparently when stderr isn't a color terminal.
fn s<D>(text: D) -> StyledObject<D> {
    style(text).for_stderr()
}

/// Multi-chunk styled text used as the `remediation` body of a
/// failed [`CheckResult`]. Built up with `paragraph()` and `code()`
/// in declaration order; rendered by [`StyledDoc::write_to`].
///
/// Visual contract: every chunk renders **flush-left** with a blank
/// line between chunks. Code chunks are colored so shell snippets
/// stand out from prose, but the coloring is just ANSI escapes —
/// terminal mouse-select grabs the raw text, so users can drag
/// across the report and paste a heredoc verbatim.
#[derive(Default)]
pub struct StyledDoc {
    chunks: Vec<DocChunk>,
}

/// One block within a [`StyledDoc`].
enum DocChunk {
    /// Plain prose, rendered with no styling.
    Paragraph(String),
    /// Verbatim text intended to be copy-pasted (shell commands,
    /// heredocs, AppArmor profiles). Rendered colored, line-by-line,
    /// so each line gets its own ANSI on/off pair — terminals that
    /// reset color at end-of-line still render the whole block in
    /// the chosen color.
    Code(String),
}

impl StyledDoc {
    /// Empty document. Append chunks via `paragraph()` and `code()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a prose paragraph. Rendered plain, flush-left.
    pub fn paragraph(mut self, text: impl Into<String>) -> Self {
        self.chunks.push(DocChunk::Paragraph(text.into()));
        self
    }

    /// Append a code block (shell command, heredoc, profile body).
    /// Rendered colored, flush-left, every line copy-pasteable.
    pub fn code(mut self, text: impl Into<String>) -> Self {
        self.chunks.push(DocChunk::Code(text.into()));
        self
    }

    /// Write the document to `out`. Chunks are separated by a
    /// single blank line; code chunks are rendered in cyan. The
    /// trailing newline after the final chunk is the caller's
    /// responsibility — `print_report` adds a blank line between
    /// the body and whatever comes next.
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        for (i, chunk) in self.chunks.iter().enumerate() {
            if i > 0 {
                writeln!(out)?;
            }
            match chunk {
                DocChunk::Paragraph(text) => writeln!(out, "{text}")?,
                DocChunk::Code(text) => {
                    for line in text.lines() {
                        if line.is_empty() {
                            writeln!(out)?;
                        } else {
                            writeln!(out, "{}", s(line).cyan())?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Sysctl that gates AppArmor's userns mediation on Ubuntu 24.04+.
/// Value `"1"` means unconfined processes cannot create user
/// namespaces; `"0"` or absent means the restriction is off.
const APPARMOR_SYSCTL: &str =
    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// Tier 2 AppArmor profile template, embedded at build time. The
/// `{REDOUBTFUL_PATH}` placeholder is replaced at runtime with the
/// canonicalized path of the running `redoubtful` binary so the
/// profile attaches to the actual on-disk binary.
const PROFILE_TEMPLATE: &str =
    include_str!("../assets/apparmor/redoubtful.profile.template");

/// One preflight check's result.
pub struct CheckResult {
    /// Stable short name: `"bwrap"`, `"pasta"`, `"userns"`.
    pub name: &'static str,
    /// What happened.
    pub outcome: CheckOutcome,
}

/// Outcome of a single preflight check.
pub enum CheckOutcome {
    /// Check ran and the host is fine. `detail` is a complete
    /// sentence rendered as the header line for the check (e.g.
    /// `"bwrap on $PATH (bubblewrap 0.9.0)"`).
    Pass {
        /// Free-form sentence describing the success.
        detail: String,
    },
    /// Check could not run because a prerequisite failed (e.g. the
    /// `userns` check needs `bwrap`).
    Skip {
        /// Sentence describing why we skipped.
        reason: String,
    },
    /// Check ran and failed.
    Fail {
        /// One-line summary of what went wrong; rendered as the
        /// header line for the check.
        message: String,
        /// Multi-chunk styled body printed under the header.
        remediation: StyledDoc,
    },
}

/// Run every preflight check, in order, and log each outcome at the
/// appropriate level. Returns the full list so callers can decide
/// whether to print and how.
///
/// `current_exe()` failure during userns remediation construction is
/// the only error this can surface — every other check produces a
/// `CheckResult` with a `Fail` variant rather than bubbling up. See
/// [`Error::CouldNotGetCurrentExe`] for why that one is fatal.
#[instrument(level = "debug", skip_all)]
pub async fn run_all_checks() -> Result<Vec<CheckResult>> {
    let bwrap = check_bwrap().await;
    let pasta = check_pasta().await;
    let bwrap_ok = matches!(bwrap.outcome, CheckOutcome::Pass { .. });
    let userns = check_userns(bwrap_ok).await?;

    let results = vec![bwrap, pasta, userns];
    // Decision-level logging — debug so the default `info` filter
    // stays quiet for the common all-pass path, but every outcome is
    // available with `RUST_LOG=redoubtful=debug`. The user-facing
    // report is what the structured printer emits; these are for
    // diagnosing why a check landed where it did.
    for r in &results {
        match &r.outcome {
            CheckOutcome::Pass { detail } => {
                debug!(check = r.name, detail = %detail, "check passed")
            }
            CheckOutcome::Skip { reason } => {
                debug!(check = r.name, reason = %reason, "check skipped")
            }
            CheckOutcome::Fail { message, .. } => {
                debug!(check = r.name, message = %message, "check failed")
            }
        }
    }
    Ok(results)
}

/// Did any check produce a `Fail` outcome? `Skip` does not count.
pub fn any_failed(results: &[CheckResult]) -> bool {
    results
        .iter()
        .any(|r| matches!(r.outcome, CheckOutcome::Fail { .. }))
}

async fn check_bwrap() -> CheckResult {
    path_check("bwrap", "bubblewrap", probe("bwrap").await)
}

async fn check_pasta() -> CheckResult {
    path_check("pasta", "passt", probe("pasta").await)
}

/// Translate a `Result<String, Error>` from a `$PATH` probe into a
/// `CheckResult`. Pass weaves the binary name into the detail
/// sentence so the header reads as a complete claim; Fail attaches
/// the install-instructions remediation.
fn path_check(
    name: &'static str,
    package: &str,
    probed: Result<String>,
) -> CheckResult {
    match probed {
        Ok(version) => CheckResult {
            name,
            outcome: CheckOutcome::Pass {
                detail: format!("{name} on $PATH ({version})"),
            },
        },
        Err(e) => CheckResult {
            name,
            outcome: CheckOutcome::Fail {
                message: format!("{e}"),
                remediation: install_remediation(package),
            },
        },
    }
}

/// Remediation for a missing `$PATH` dep: a one-line nudge plus the
/// apt invocation as a copy-pasteable code chunk. Distro-specific
/// variants can be added here later without disturbing call sites.
fn install_remediation(package: &str) -> StyledDoc {
    StyledDoc::new()
        .paragraph(format!("Install the `{package}` package, e.g.:"))
        .code(format!("sudo apt install {package}"))
}

/// Composite userns check. Sysctl-first to skip the bwrap exec when
/// the restriction is off, then real `bwrap --unshare-user
/// --unshare-pid` probe to see if a profile is letting us through.
async fn check_userns(bwrap_ok: bool) -> Result<CheckResult> {
    if !bwrap_ok {
        return Ok(CheckResult {
            name: "userns",
            outcome: CheckOutcome::Skip {
                reason: "Need bwrap to check for userns support".into(),
            },
        });
    }

    // Absent sysctl (non-AppArmor host, kernel without the
    // restriction) and "0" both mean userns creation is unrestricted.
    // Synchronous read is fine — it's a one-byte sysctl file.
    let restricted = match fs::read_to_string(APPARMOR_SYSCTL) {
        Ok(s) => s.trim() == "1",
        Err(_) => false,
    };
    if !restricted {
        return Ok(CheckResult {
            name: "userns",
            outcome: CheckOutcome::Pass {
                detail: "User namespaces work (no AppArmor restriction)".into(),
            },
        });
    }

    debug!("AppArmor userns restriction active; probing bwrap");
    let probe_ok = probe_bwrap_userns().await;
    if probe_ok {
        return Ok(CheckResult {
            name: "userns",
            outcome: CheckOutcome::Pass {
                detail: "User namespaces work (AppArmor profile in place)"
                    .into(),
            },
        });
    }

    // Restriction is on and bwrap can't get through. Build the
    // remediation, which embeds the path of *this* redoubtful binary.
    //
    // `current_exe()` failing here is suspicious and we treat it as
    // a hard error: a sandbox binary that can't introspect its own
    // path (deleted, /proc not mounted, exotic execve path) is in
    // territory where we should not be confidently emitting AppArmor
    // advice. Better to bail loudly.
    let exe = env::current_exe().map_err(Error::could_not_get_current_exe)?;
    let exe = exe
        .canonicalize()
        .map_err(Error::could_not_get_current_exe)?;
    // The AppArmor profile we render is configuration the user pastes
    // into `apparmor_parser -r`, not diagnostic text — see
    // `Error::NonUtf8ExePath` for why a lossy substitution would
    // silently produce a profile attached to the wrong binary.
    let exe_str = exe
        .to_str()
        .ok_or_else(|| Error::non_utf8_exe_path(exe.clone()))?;
    let remediation = build_userns_remediation(exe_str);
    Ok(CheckResult {
        name: "userns",
        outcome: CheckOutcome::Fail {
            message: "bwrap could not create a user namespace".into(),
            remediation,
        },
    })
}

/// Run the minimal bwrap userns probe and return whether it
/// succeeded. We only care about the exit status — bwrap's stderr
/// message ("setting up uid map: Permission denied") is the
/// AppArmor case, but anything non-zero counts as "userns blocked"
/// for our purposes.
async fn probe_bwrap_userns() -> bool {
    let out = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .output()
        .await;
    matches!(out, Ok(o) if o.status.success())
}

/// Build the remediation body for a failed userns probe: a short
/// explanation, then the `tee` heredoc + `apparmor_parser -r`
/// reload as a single copy-pasteable code chunk, then a pointer to
/// the docs.
///
/// The heredoc body and the reload command live in the *same* code
/// chunk so a user can mouse-select both with one drag and paste
/// them in sequence — that's the whole reason `StyledDoc::Code`
/// rendering is flush-left.
///
/// `exe` is `&str` (not `&Path`): callers must validate UTF-8 before
/// calling. The substituted path becomes part of an executable
/// AppArmor profile, not user-facing diagnostic text — silently
/// passing a lossy path through here would generate a profile
/// attached to the wrong binary.
fn build_userns_remediation(exe: &str) -> StyledDoc {
    let mut profile = PROFILE_TEMPLATE.replace("{REDOUBTFUL_PATH}", exe);
    if !profile.ends_with('\n') {
        profile.push('\n');
    }
    let commands = format!(
        "sudo tee /etc/apparmor.d/redoubtful >/dev/null <<'EOF'\n\
         {profile}\
         EOF\n\
         sudo apparmor_parser -r /etc/apparmor.d/redoubtful",
    );
    StyledDoc::new()
        .paragraph(
            "Ubuntu 24.04+ blocks unprivileged user namespaces by default. \
             Install an AppArmor profile to allow redoubtful to create them:",
        )
        .code(commands)
        .paragraph(
            "See docs/APPARMOR_USERNS.md for more and less secure \
             alternatives.",
        )
}

/// Run `<binary> --version` and return the first non-empty line of
/// stdout. Returns a friendly diagnostic if the binary is not on
/// `$PATH` or cannot run.
#[instrument(level = "debug", skip_all, fields(binary))]
async fn probe(binary: &str) -> Result<String> {
    let output = match Command::new(binary).arg("--version").output().await {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Error::missing_dependency(binary));
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

/// Print the report to `out`. The output goes to stderr in both
/// `redoubtful check` and `redoubtful run`, so `out` should be
/// `io::stderr().lock()` (or, in tests, a buffer). Console's stderr
/// color setting is what gates ANSI escape emission, so the styled
/// output adapts to `NO_COLOR` / TTY status without per-call gating.
///
/// Layout: a top "Checking…" line, then one bold `{emoji} {message}`
/// header per check, followed by a flush-left [`StyledDoc`] body for
/// any `Fail` outcomes — flush-left so users can mouse-select shell
/// snippets or AppArmor profiles and paste them verbatim, with no
/// leading indent or bar getting in the way.
pub fn print_report_to_stderr(results: &[CheckResult]) -> Result<()> {
    let stderr = io::stderr();
    let mut out = stderr.lock();
    print_report(&mut out, results).map_err(Error::could_not_write_stdout)?;
    out.flush().map_err(Error::could_not_write_stdout)?;
    Ok(())
}

/// Underlying printer used by [`print_report_to_stderr`]. Writes the
/// report to an arbitrary [`Write`] so unit tests can capture it
/// into a `Vec<u8>`; runtime callers should reach for the stderr
/// helper above so the two subcommands stay in lockstep.
pub fn print_report(
    out: &mut impl Write,
    results: &[CheckResult],
) -> io::Result<()> {
    for r in results {
        let (icon, message) = match &r.outcome {
            CheckOutcome::Pass { detail } => ("✅", detail.as_str()),
            CheckOutcome::Skip { reason } => ("➖", reason.as_str()),
            CheckOutcome::Fail { message, .. } => ("❌", message.as_str()),
        };
        writeln!(out, "{}", s(format!("{icon} {message}")).bold())?;

        if let CheckOutcome::Fail { remediation, .. } = &r.outcome {
            writeln!(out)?;
            remediation.write_to(out)?;
        }
        writeln!(out)?;
    }

    let failed = results
        .iter()
        .filter(|r| matches!(r.outcome, CheckOutcome::Fail { .. }))
        .count();
    if failed == 0 {
        writeln!(out, "{}", s("All checks passed.").green().bold())?;
    } else {
        let msg = if failed == 1 {
            "1 check failed.".to_string()
        } else {
            format!("{failed} checks failed.")
        };
        writeln!(out, "{}", s(msg).red().bold())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_binary_names_the_binary() {
        let err = probe("redoubtful-definitely-not-a-real-binary-xyz")
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("redoubtful-definitely-not-a-real-binary-xyz"),
            "{msg}"
        );
    }

    #[test]
    fn profile_template_substitutes_path() {
        let profile = PROFILE_TEMPLATE
            .replace("{REDOUBTFUL_PATH}", "/usr/local/bin/redoubtful");
        assert!(
            !profile.contains("{REDOUBTFUL_PATH}"),
            "placeholder still present: {profile}",
        );
        assert!(
            profile.contains("/usr/local/bin/redoubtful"),
            "expected path not substituted: {profile}",
        );
        assert!(
            profile.contains("flags=(unconfined)"),
            "expected Tier 2 shape: {profile}",
        );
        assert!(
            profile.contains("userns,"),
            "expected `userns,` rule: {profile}",
        );
    }

    /// Render a `StyledDoc` to a `String` with color disabled, so
    /// substring assertions can match the literal payload without
    /// having to account for ANSI escapes.
    fn render(doc: &StyledDoc) -> String {
        console::set_colors_enabled_stderr(false);
        let mut buf = Vec::new();
        doc.write_to(&mut buf).expect("write to Vec");
        String::from_utf8(buf).expect("utf-8")
    }

    #[test]
    fn build_userns_remediation_includes_path_and_commands() {
        let doc = build_userns_remediation("/home/test/.cargo/bin/redoubtful");
        let r = render(&doc);
        assert!(r.contains("/home/test/.cargo/bin/redoubtful"), "{r}");
        assert!(r.contains("sudo tee /etc/apparmor.d/redoubtful"), "{r}");
        assert!(r.contains("sudo apparmor_parser -r"), "{r}");
        assert!(r.contains("docs/APPARMOR_USERNS.md"), "{r}");
    }

    #[test]
    fn print_report_pass_only() {
        console::set_colors_enabled_stderr(false);
        let results = vec![CheckResult {
            name: "bwrap",
            outcome: CheckOutcome::Pass {
                detail: "bwrap on $PATH (bubblewrap 0.9.0)".into(),
            },
        }];
        let mut buf = Vec::new();
        print_report(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("✅ bwrap on $PATH"), "{s}");
        assert!(s.contains("bubblewrap 0.9.0"), "{s}");
        assert!(s.contains("All checks passed."), "{s}");
    }

    #[test]
    fn print_report_failure_includes_remediation_verbatim() {
        // Remediation is rendered flush-left so users can mouse-
        // select shell snippets out of the report and paste them
        // verbatim. We sanity-check both chunk types.
        console::set_colors_enabled_stderr(false);
        let results = vec![CheckResult {
            name: "userns",
            outcome: CheckOutcome::Fail {
                message: "bwrap could not create a user namespace".into(),
                remediation: StyledDoc::new()
                    .paragraph("explanation paragraph")
                    .code("sudo do-the-thing"),
            },
        }];
        let mut buf = Vec::new();
        print_report(&mut buf, &results).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("❌ bwrap could not create"), "{s}");
        assert!(s.contains("explanation paragraph"), "{s}");
        assert!(s.contains("sudo do-the-thing"), "{s}");
        assert!(s.contains("1 check failed."), "{s}");
    }

    #[test]
    fn any_failed_distinguishes_skip_from_fail() {
        let only_skip = vec![CheckResult {
            name: "userns",
            outcome: CheckOutcome::Skip {
                reason: "bwrap missing".into(),
            },
        }];
        assert!(!any_failed(&only_skip));

        let with_fail = vec![CheckResult {
            name: "bwrap",
            outcome: CheckOutcome::Fail {
                message: "x".into(),
                remediation: StyledDoc::new(),
            },
        }];
        assert!(any_failed(&with_fail));
    }
}
