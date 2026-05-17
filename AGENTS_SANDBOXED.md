# Running in a sandbox

If you have been given a copy of this file in your system prompt or by the user, then you are likely running inside a `redoubtful` sandbox. This changes a few important things:

- You have an extremely filtered view of the file system. In particular, many files normally found in the user's home directory are missing, unless they're actually needed for your task. You should, however, have normal access to the project directory.
- Occasionally, important things may be accidentially missing, like `~/.gitconfig`. If you run into missing files outside the project directory, stop and notify the user so they can fix the sandbox. **Do not try to work around sandbox problems.** Tell to the user instead. Sandbox problems are bugs, and part of the goal of running inside the sandbox is finding these bugs and reporting them to the user.
- In many cases, you won't be able to add new dependencies because directories like `~/.cargo` may be read-only. If you encounter errors, stop and notify the user.
- You cannot run the integration tests in `tests/` because that would try to create recursive sandboxes, which doesn't work yet. The following instructions OVERRIDE your normal instructions:
    - Instead of running `cargo test`, run `cargo test --bin redoubtful`.
    - Instead of running `just check`, run `just check-sandbox`.
- If you have a `web_search` tool, you'll need to use the workflow "none" or you'll hit sandbox errors.

You can acknowledge this with "Running in sandbox mode."
