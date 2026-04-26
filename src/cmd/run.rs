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

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt as _;

use tokio::process::Command;
use tokio::signal::unix::{SignalKind, signal};

use crate::bwrap::bwrap_argv;
use crate::env::{EnvList, EnvOpts};
use crate::forward::{ForwardList, ForwardOpts};
use crate::mounts::{MountList, MountOpts, current_dir, home_dir};
use crate::pasta::pasta_argv;
use crate::prelude::*;

/// Arguments to `redoubtful run`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// `-m, --mount` and `--readonly` flags.
    #[command(flatten)]
    pub mount_opts: MountOpts,

    /// `-f, --forward` flags.
    #[command(flatten)]
    pub forward_opts: ForwardOpts,

    /// `-e, --env` and `--path` flags.
    #[command(flatten)]
    pub env_opts: EnvOpts,

    /// The command to execute, e.g. `redoubtful run cargo build`.
    #[arg(value_name = "COMMAND")]
    pub command: String,

    /// Arguments to pass to the command. Hyphen-prefixed args pass through
    /// as-is.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "ARGS"
    )]
    pub args: Vec<String>,
}

/// Execute `<command> [args...]` inside a pasta + bwrap sandbox.
#[instrument(level = "debug", name = "run", skip_all)]
pub async fn cmd_run(args: Args) -> Result<()> {
    let Args {
        mount_opts,
        forward_opts,
        env_opts,
        command,
        args,
    } = args;
    debug!(command, ?args, "executing command in sandbox");

    // Validate CLI mount sources up-front so we don't fail deep
    // inside bwrap setup with a less helpful diagnostic.
    mount_opts.validate()?;

    // ----- Build the mount and forward inventories -----
    let home = home_dir()?;
    let cwd = current_dir()?;
    let mut mounts =
        MountList::default_baseline(&home, &cwd, mount_opts.cwd_access());
    mount_opts.apply(&mut mounts);

    let mut forwards = ForwardList::default_baseline();
    forward_opts.apply(&mut forwards);

    // ----- Build the env inventory -----
    //
    // `default_baseline` resolves passthroughs against the host env
    // now, so by the time we hand `&env` to bwrap_argv every entry
    // has a concrete value. The same `home` path is reused for
    // `$HOME` here and for the bind-mount layer above so env and
    // mounts agree on where the agent's files live.
    let mut env = EnvList::default_baseline(
        &home,
        env_opts.path.as_deref(),
        &env_opts.path_add,
    );
    env_opts.apply(&mut env);

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

    // The user's mental model is that their command is what ran;
    // surface that in error variants alongside the pasta+bwrap
    // wrapping so the diagnostic stays honest.
    let cmd_summary = format!("pasta bwrap {}", command);
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
