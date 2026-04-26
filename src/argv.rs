//! Shared `argv` accumulator used by the bwrap and pasta builders.
//!
//! The two external commands have very similar argv shapes — a long
//! flag list with paths, sometimes paired with values, sometimes
//! standalone — so they share an `OsString`-based builder rather
//! than each open-coding `Vec<OsString>` mutation. Keeps each call
//! site one logical step per line and centralizes the (boring,
//! correct) `OsString::from`/`as_os_str().to_owned()` boilerplate.
//!
//! There is intentionally no escaping or quoting here: argv tokens
//! pass directly to `execve`, which does not interpret quotes. The
//! builder's only job is to keep the `Vec<OsString>` legible at the
//! call site.
//!
//! References:
//!
//!   bwrap(1) manpage:
//!     <https://man.archlinux.org/man/bwrap.1.en>
//!   pasta(1) manpage:
//!     <https://passt.top/builds/latest/web/passt.1.html>

use std::ffi::OsString;
use std::path::Path;

/// Internal accumulator of `OsString` argv tokens.
///
/// The builder is `pub(crate)` because both `bwrap.rs` and `pasta.rs`
/// construct one; it is not part of the crate's public surface.
#[derive(Default)]
pub struct ArgvBuilder {
    argv: Vec<OsString>,
}

impl ArgvBuilder {
    /// Append a single bare flag token (e.g. `--unshare-all`).
    pub fn flag(&mut self, s: &str) {
        self.argv.push(OsString::from(s));
    }

    /// Append `flag` followed by a single path operand
    /// (e.g. `--tmpfs /tmp` or `--chdir <cwd>`).
    pub fn single_path(&mut self, flag: &str, p: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(p.as_os_str().to_owned());
    }

    /// Append `flag` followed by two path operands
    /// (e.g. `--ro-bind <host> <sandbox>`).
    pub fn pair_path(&mut self, flag: &str, a: &Path, b: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(a.as_os_str().to_owned());
        self.argv.push(b.as_os_str().to_owned());
    }

    /// Append `flag` followed by a string operand and a path operand
    /// (e.g. `--symlink usr/bin /bin`).
    pub fn pair_str_path(&mut self, flag: &str, a: &str, b: &Path) {
        self.argv.push(OsString::from(flag));
        self.argv.push(OsString::from(a));
        self.argv.push(b.as_os_str().to_owned());
    }

    /// Append `flag` followed by a single string operand
    /// (e.g. `-T 8080,8081`).
    pub fn pair_str(&mut self, flag: &str, value: &str) {
        self.argv.push(OsString::from(flag));
        self.argv.push(OsString::from(value));
    }

    /// Append `flag` followed by two string operands
    /// (e.g. `--setenv PATH /usr/bin`). Bwrap's `--setenv` takes the
    /// name and value as separate argv tokens, so a 2-string pair
    /// helper avoids reconstructing `OsString` boilerplate at the
    /// call site.
    pub fn triple_str(&mut self, flag: &str, a: &str, b: &str) {
        self.argv.push(OsString::from(flag));
        self.argv.push(OsString::from(a));
        self.argv.push(OsString::from(b));
    }

    /// Append a sequence of pre-built `OsString` tokens verbatim.
    /// Used for the inner command's argv, which we already have as
    /// `Vec<OsString>`.
    pub fn extend_os(&mut self, tokens: impl IntoIterator<Item = OsString>) {
        self.argv.extend(tokens);
    }

    /// Append a slice of `String` arguments verbatim. Used for the
    /// user command's CLI arguments, which arrive from clap as
    /// `Vec<String>`.
    pub fn extend_args(&mut self, args: &[String]) {
        for a in args {
            self.argv.push(OsString::from(a));
        }
    }

    /// Consume the builder and return the assembled argv.
    pub fn into_vec(self) -> Vec<OsString> {
        self.argv
    }
}
