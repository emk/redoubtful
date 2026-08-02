# WORK IN PROGRESS: `redoubtful`, a lightweight Linux agent sandbox

_**WARNING:** This is incomplete work-in-progress, and nearly all of the code was written by Claude Opus 4.7 and Qwen 3.6 27B. This is one of my "how good are agents this month?" projects._

`redoubtful` is designed to be a lightweight agent sandbox that tries to make it semi-reasonable to use `--dangerously-skip-permissions`. It uses `pasta` and `bwrap` to:

- Create a fake filesystem that contains a highly restricted view of the real filesystem. (But we preserve paths and file ownership, so `git worktree` should work.)
- Clean up environment variables to prevent credential leakage.
- Control network access.
- TODO: Run an HTTPS proxy which holds actual network credentials.

This is _not_ trying to be a Docker container, or a browser-style security sandbox. This is designed to let you take a small local model and `--dangerously-skip-permissions` (etc) and hopefully not burn down anything besides the current working directory. 

## Implementation status

- [x] Basic `pasta` configuration for locking down the network and mapping host ports into the sandbox.
- [x] Basic `bwrap` configuration for locking down the rest of the environment.
- [x] Nice ergonomic configuration files.
- [ ] HTTPS proxy + credential storage.

## Usage

You can run `opencode` in the sandbox using:

```sh
redoubtful run \
    -m ~/.opencode -m ~/.config/opencode -p ~/.opencode/bin \
    -f 8080 opencode
```

The `-f 8080` will map `localhost:8080` into the sandbox (for `llama-server`), and set up your mount points and paths to run `opencode`. Eventually it would be nice to offer named profiles so you didn't need to type all this.

There are also "profiles." Take a look at `~/.config/redoubtful/config.toml`, which is created on first run. Make sure it correctly matches your `npm` and other tool locations. Then run:

```sh
redoubtful run -u pi pi
```

## Installation (Linux)

`redoubtful` only works on Linux. Clone this repository and run:

```sh
cargo install --path .
```

You will also need `bwrap` and `pasta`. On Ubuntu, you can install them with:

```sh
sudo apt install bubblewrap passt
```

### Enabling user namespaces (Ubuntu 24.04)

Under a stock Linux kernel, things should work without further setup. But Ubuntu quite rightfully distrusts Linux's support for user namespaces. In _theory_, user namespaces don't let users do anything they couldn't before. In practice, they allow users to _try_ making kernel calls against features originally designed only for root users. Which has led to some nasty CVEs in the past. So we need to tell Ubuntu to allow `redoubtful` to use `userns`.

Create `/etc/apparmor.d/redoubtful-cargo-bin.profile`, replacing "USER" with your username:

```
profile redoubtful-cargo-bin /home/USER/.cargo/bin/redoubtful flags=(unconfined) {
  userns,
  include if exists <local/redoubtful>
}
```

Then run:

```sh
sudo apparmor_parser -r /etc/apparmor.d/redoubtful-cargo-bin.profile
```

This gives `redoubtful` the same permissions as something like Firefox or `flatpak`. Which isn't great, because you can shell into `redoubtful`, recursively create a _second_ set of user namespaces with a full set of capabilities, and then poke at the kernel to look for CVEs.

**A better alternative.** Take a look at `/etc/apparmor.d/unprivileged_userns` and see how that trick works. Combine that with:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1
```

...and you may actually get somewhere. We may expand on this in the future, or explore other sandboxing mechanisms.

**A worse alternative.** If you don't mind opening up a whole bunch of attack surface, you could always do:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

This disables Ubuntu's hardening, putting you back at the Linux defaults. But if you had done this in the past, you would have been exposed to a whole set of CVEs.

## AI Policy

This project is meant for sandboxing dodgy AI tools, including overenthusiatic local models that occasionally make mistakes. The code is almost entirely AI-written, under moderate to close human supervision, including human code review. Early work was done using Claude Opus 4.7, but as open models improved, the work is almost entirely done using models with MIT-licensed weights running under the [Pi](https://pi.dev/) coding harness _inside_ a `redoubtful` sandbox. There may be a few AI-written commits that aren't tagged as such, but most should have `Co-Authored-By` or `Assisted-by:` (preferred).

However, this does not necessarily mean I'll read AI-written PRs, unless they're clear, short and do something important. If you want to propose something large or complicated, please file a human-written issue first! If large features are going to be implementing using AI, I would just as soon supervise that process.
