//! `redoubtful run`: execute a command inside the sandbox.
//!
//! Process tree assembled here:
//!
//! ```text
//! redoubtful → pasta → bwrap → user command
//! ```
//!
//! Pasta owns the network namespace (private loopback, no route to
//! the host or Internet, explicit host-port forwards via `-T`).
//! Bwrap owns mount/pid/user/ipc/uts/cgroup namespaces and inherits
//! pasta's netns through `--share-net`. We are pasta's parent, so
//! we set `PR_SET_PDEATHSIG = SIGTERM` on it via a `pre_exec` hook;
//! pasta's `--die-with-parent`-like behavior is supplied by bwrap's
//! `--die-with-parent` for the bwrap → user-command leg. Together
//! the chain unwinds top-down if redoubtful itself is killed.

// Spawning pasta with a `pre_exec` hook calls into a deliberately
// `unsafe fn` on `CommandExt`. This is exactly the kind of OS
// primitive the workspace lint comment carves out — see Cargo.toml.
#![allow(unsafe_code)]

use std::{ffi::OsString, os::unix::process::ExitStatusExt as _};

use tokio::{
    process::Command,
    signal::unix::{SignalKind, signal},
};

use crate::{
    check::{any_failed, print_report_to_stderr, run_all_checks},
    config::{
        Finalize,
        config_file::ConfigFile,
        profile::{Profile, ProfileDecl},
    },
    dirs::current_dir,
    prelude::*,
    sandbox::{bwrap_argv, pasta_argv, proxy_profile, start_proxy},
};

/// Arguments to `redoubtful run`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[clap(flatten)]
    pub profile: ProfileDecl,

    /// The command to execute, e.g. `redoubtful run cargo build`.
    /// `OsString` so a non-UTF-8 binary name on the host (rare but
    /// possible) reaches `execve` byte-for-byte.
    #[arg(value_name = "COMMAND")]
    pub command: OsString,

    /// Arguments to pass to the command. Hyphen-prefixed args pass through
    /// as-is. `OsString` so any byte the user could pass on a Unix
    /// command line survives into the sandboxed argv.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub args: Vec<OsString>,
}

/// Execute `<command> [args...]` inside a pasta + bwrap sandbox.
#[instrument(level = "debug", name = "run", skip_all)]
pub async fn cmd_run(args: Args) -> Result<()> {
    let Args {
        profile,
        command,
        args,
    } = args;
    debug!(?command, ?args, "executing command in sandbox");

    // Preflight: verify bwrap/pasta are on PATH and user namespaces
    // can be created. On failure, emit the same report `redoubtful
    // check` would print (to stderr — this isn't the user's
    // requested output) and exit before touching the sandbox setup.
    // On success, stay silent: `redoubtful run` is the hot path.
    let results = run_all_checks().await?;
    if any_failed(&results) {
        print_report_to_stderr(&results)?;
        return Err(Error::exit("redoubtful run", 1));
    }

    // ----- Build the mount/forward/env inventories -----
    //
    // [`ConfigFile::finalize_config_with_cli`] owns the load-config →
    // normalize-paths → resolve-uses → validate → resolve-decls →
    // merge → finalize pipeline. `cmd_show` calls the same helper so
    // both commands describe identical sandbox configurations for
    // identical arguments. Even when no `-p` was passed we still go
    // through it: a malformed config surfaces as a span-rendered
    // miette diagnostic on the next run rather than lying dormant.
    let cwd = current_dir()?;
    let user_profile = ConfigFile::finalize_config_with_cli(&profile)?;

    // ----- Start the credential proxy -----
    //
    // Stage 1 is tunnel-only: the proxy accepts CONNECT, resolves
    // hostnames host-side, and pipes bytes (no MITM, no credential
    // injection). This is what makes anything in the sandbox reach
    // the internet — without it, clients see "no DNS, no route" and
    // hang on `getaddrinfo`. See `crate::sandbox::proxy` for the rationale
    // behind the throwaway CA.
    //
    // We merge the proxy's resolved profile into the user's finalized
    // profile. The proxy contributes one same-port forward and 8 env
    // vars (HTTPS_PROXY and friends). Since this merge happens after
    // finalization, the proxy profile is a raw `Profile` — no `path`,
    // `path_add`, or `readonly` extras (finalization is a one-time
    // operation). Right-biased merge means proxy env vars win on any
    // key collision, which is correct: the user shouldn't be able to
    // break the proxy by setting `HTTPS_PROXY` to something else.
    let proxy_handle = start_proxy().await?;
    debug!(port = proxy_handle.port, "credential proxy listening");
    let profile_with_proxy =
        user_profile.merge_right_biased(&proxy_profile(proxy_handle.port));

    let Profile {
        mounts,
        forwards,
        env,
    } = profile_with_proxy;

    // ----- Assemble bwrap and pasta argvs -----
    let bwrap_args = bwrap_argv(&mounts, &env, &cwd, &command, &args);
    let mut child_argv = Vec::with_capacity(bwrap_args.len().saturating_add(1));
    child_argv.push(OsString::from("bwrap"));
    child_argv.extend(bwrap_args);
    let pasta_args = pasta_argv(&forwards, child_argv);
    debug!(cmd = "pasta", args = ?pasta_args, "running sandbox");

    // ----- Spawn pasta with PR_SET_PDEATHSIG -----
    //
    // Without this, if `redoubtful` itself dies abruptly (panic,
    // SIGKILL, the user closing its terminal — anything that
    // doesn't run our normal cleanup), pasta gets reparented to
    // PID 1 and keeps running. Pasta keeps the netns alive, bwrap
    // (whose own --die-with-parent ties it to pasta) keeps the
    // user command alive, and the user is left with a sandboxed
    // agent that they thought they killed minutes ago, still
    // burning tokens / writing files / making network calls.
    //
    // PR_SET_PDEATHSIG closes that gap. The kernel records, on
    // the about-to-be-pasta task, "if your parent dies, send
    // yourself this signal." When redoubtful dies, the kernel
    // sends pasta SIGTERM directly — no bookkeeping on our side,
    // no race window. The full death chain becomes:
    //
    //   redoubtful dies → kernel SIGTERMs pasta (this prctl)
    //                   → pasta exits, kernel SIGKILLs bwrap
    //                     (bwrap's --die-with-parent)
    //                   → bwrap exits, pid-namespace teardown
    //                     reaps the user command
    //
    // SIGTERM (not SIGKILL) gives pasta a chance to tear down
    // its tap interface gracefully; if pasta ignores it we don't
    // really care, since the kernel will reap it eventually
    // either way and the netns goes with it.
    //
    // Subtle gotcha (not a problem for us, but worth a note):
    // PR_SET_PDEATHSIG fires when the parent *thread* exits, not
    // the parent process. We're fine because redoubtful's main
    // task is the one that spawned pasta and the one that's
    // awaiting it; if the main thread is gone, redoubtful is
    // gone, which is exactly when we want pasta to die.
    //
    //   <https://man7.org/linux/man-pages/man2/prctl.2.html>
    //   bwrap(1) `--die-with-parent` for the next link in the chain.
    let mut cmd = Command::new("pasta");
    cmd.args(&pasta_args);
    // SAFETY: `set_pdeathsig` is a pure prctl call with no
    // allocation, no FFI callbacks, and no shared mutable state —
    // safe to run between fork() and execve(). The `pre_exec`
    // closure runs in the child after fork; `capctl` wraps the raw
    // prctl in a normal Rust function, so the only `unsafe` here is
    // the `pre_exec` invocation itself.
    unsafe {
        cmd.pre_exec(|| {
            capctl::prctl::set_pdeathsig(Some(libc::SIGTERM))
                .map_err(std::io::Error::from)
        });
    }

    let mut child =
        cmd.spawn().map_err(|e| Error::could_not_run("pasta", e))?;

    // ----- Wait for pasta, forwarding signals -----
    //
    // Terminal SIGINT already reaches pasta via the controlling
    // pgrp, but explicit SIGINT/SIGTERM forwarding handles the
    // `kill -TERM <our-pid>` case where signals are sent to us
    // directly. `start_kill` sends SIGKILL — this is a hard exit;
    // graceful shutdown is a follow-up if it ever matters.
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|e| Error::could_not_run("install SIGINT handler", e))?;
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| Error::could_not_run("install SIGTERM handler", e))?;

    let status = loop {
        tokio::select! {
            res = child.wait() => {
                break res.map_err(|e| Error::could_not_run("pasta", e))?;
            }
            _ = sigint.recv() => {
                debug!("forwarding SIGINT to pasta child");
                let _ = child.start_kill();
            }
            _ = sigterm.recv() => {
                debug!("forwarding SIGTERM to pasta child");
                let _ = child.start_kill();
            }
        }
    };

    // Tear the proxy down before we render the sandbox's exit
    // status. The runtime drop on process exit would clean it up
    // anyway, but an explicit shutdown lets graceful_shutdown
    // actually drain in-flight tunnels and keeps the debug log
    // honest. Errors awaiting the task are swallowed inside
    // `shutdown` — the user's exit code is the load-bearing thing
    // here, not the proxy's last gasp.
    proxy_handle.shutdown().await;

    // The user's mental model is that their command is what ran;
    // surface that in error variants alongside the pasta+bwrap
    // wrapping so the diagnostic stays honest. The command is an
    // `OsString` to preserve byte-clean argv on the way down — but
    // by the time we're rendering an exit-code diagnostic, we're
    // squarely in user-facing diagnostic territory where the
    // policy permits silent lossy display.
    let cmd_summary = format!("pasta bwrap {}", command.to_string_lossy());
    match (status.code(), status.signal()) {
        (Some(0), _) => Ok(()),
        (Some(code), _) => Err(Error::exit(cmd_summary, code)),
        (None, Some(signal)) => Err(Error::signal(cmd_summary, signal)),
        (None, None) => {
            warn!(
                "process terminated without exit code or signal; treating as exit code 1"
            );
            Err(Error::exit(cmd_summary, 1))
        }
    }
}
