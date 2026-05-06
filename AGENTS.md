# redoubtful: Simple Linux agent sandbox

**PROJECT STATUS:** Initial development, iterating heavily to improve ergonomics. Breaking changes are fair game.

## Layout

- `docs/`: Permanent reference docs, in Markdown.
    - `ARCHITECTURE.md`: Original architecture notes.
    - `SECURITY_PHILOSOPHY.md`: Overview of our security philosophy.
- `plans/`: More emphemeral planning docs, in Markdown. Must have a "> **Status:**" line under the title.
- `src/`:
    - `cmd/`: Command-line interface.
    - `config/`: Config file handing and share CLI argument types.
    - `prelude.rs`: Key imports used everywhere.
    - `sandbox/`: Actual sandbox implementation.
- `tests/`: Integration tests for the CLI interface.
    - `cli.rs`: Main integration test binary.
    - `fixtures/`: Files and directories needed to test.

## Useful commands

- Standard `cargo` commands: `check`, `test`, etc. are available.
- Use `cargo add` to add dependencies.
- Run `just check` before **every commit!** Your code cannot be merged until this passes.

## Coding Philosophy

> There are two ways of constructing a software design: One way is to make it so simple that there are obviously no deficiencies, and the other way is to make it so complicated that there are no obvious deficiencies. —C.A.R. Hoare

We strive for "so simple there are obviously no deficiencies."

There are often three stages in a programmer's learning:

1. "Cowboy coding": Throw code at it and hope it works.
2. Overengineering: Lots of complexity everywhere, like an "Enterprise FizzBuzz" meme.
3. Simple and correct: Just the code that we need, nothing more. Make the right design look effortless.

We aim for the third.

We aim to reduce duplication, but not at the expense of adding significant complexity. Pulling out duplicated code into functions and giving them a good name is great. Resorting to writing proc macros in order to save a few characters is a false economy.

Even in tests, we strive for clarity and minimal boilerplate. We use `mod tests { .. }`, we extract boilerplate into functions, and we prefer test cases with `let examples = &[...]` and a loop over many near-indentical `#[test]` functions with the same boilerplate.

We believe in secure, correct code with good test coverage.

## Rust Coding Guidlines

### Error Handling

For error handling, we use a custom `Error` enum and `Result` type in `src/errors.rs`. All errors will need to be converted to this type, and there is not currently a fallback like "`Other`", so take a look at how it works and add enum variants as necessary.

We only use `unwrap` and `except` as true assertions, for programmer errors and things that "can't happen." (And of course, they're fine in tests.) If you use them, prefer `expect` because it includes documentation, and leave a 1-line comment explaining why the condition should never happen.

### Prelude

The most common definitions, including error-handling and logging, are available via `use crate::prelude::*;`.

### Documentation

All public items must be documented.

### String vs OsString, and "lossy" conversion functions

This program frequently manipulates paths and environment variables, which can be losslessly-represented using Path, Pathbuf, OsStr and OsString. The rules are:

- It is only acceptable to silently loose non-UTF8 data in user-facing diagnostic output.
- If we cannot preserve non-UTF-8 data on other code paths, it is better to error cleanly.
- Our configuration files are UTF-8 only, and this is OK.
- It is fine to support OsString in CLI arguments, environment variables, etc., if this does not add too much complexity.

The overall principle is that non-UTF-8 data is a reality, and we would prefer to handle it correctly. But there may be edge cases (like config files) where this is poorly-supported, and that's OK.

### Unsafe Code

Unsafe code is forbidden, except cases where we need to bind operating-system-specific APIs for correctness.

### Arithmetic and Numeric Conversionsg 

Don't use arithmetic that can panic on overflow. Use `checked_*`, `saturating_*`, or `wrapping_*` methods instead. Whenever feasible, propagate and report failures as errors.

Avoid `as` casts for numeric conversions. Prefer `From` or `TryFrom`, and propagate errors up the call chain.

### Transmute

No `transmute` calls.

### Deserializing

Use `serde` or well-known crates instead of parsing types like `serde_json::Value` by hand.

### Logging and Tracing

We use `tracing` for structured logging. Follow these conventions:

1. **CLI/network calls**: Functions that call external tools or the network should have `#[instrument(level = "debug", skip_all, fields(...))]`. Include only interesting fields. If a public wrapper just delegates to an internal function, instrument the public wrapper.

2. **Command handlers**: Functions in `cmd::` that implement commands should also have `#[instrument(level = "debug", name = "subcommand_name", skip_all)]`. The CLI parameters are logged once at the start.

3. **Decision logging**: Log key decisions with `debug!(key = value, "message")`. Prefer structured logging over string interpolation.

4. **Search loops**: When iterating to search for something, you can use `trace!` from inside the loop to help diagnose filtering behavior.

Control log levels with `RUST_LOG`, e.g., `RUST_LOG=redoubtful=debug,info` or `RUST_LOG=redoubtful=trace,info`. We have a fair bit of tracing which you can use to figure out how decisions are made internally.
