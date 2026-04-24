

# Look up our CLI version (which should match our other package versions).
VERSION := `cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "redoubtful") | .version'`

# Run all our pre-commit checks.
check:
    cargo fmt -- --check # +nightly is even better, but not always available.
    cargo clippy --all-targets --all-features -- -D warnings
    cargo deny check
    cargo test --all-features

# Print the current version.
version:
    @echo "{{VERSION}}"

# Push a release tag.
release: check
    git tag v{{VERSION}}
    git push
    git push --tags
