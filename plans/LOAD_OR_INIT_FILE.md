# LoadOrInitFile trait: unify config and secrets auto-init

> **Status:** Implemented.

## Background

`ConfigFile` and the secrets file both follow the same auto-init pattern:
read → NotFound → write default → re-read → parse. The logic is duplicated
across `config_file.rs` and `resolve_context.rs` with different parse steps,
error variants, and default content.

## Design

### 1. `SecretsFile` type

Define a `#[serde(transparent)]` wrapper so `toml::from_str` works directly
without a manual `toml::Value` → `serde_json::Value` conversion:

```rust
#[derive(Debug, Clone)]
#[serde(transparent)]
pub struct SecretsFile(serde_json::Value);
```

`serde_json::Value` implements `Deserialize` generically — it accepts any
serde event stream. TOML's deserializer produces exactly that, so
`toml::from_str::<SecretsFile>(source)` should deserialize the TOML directly
into a `serde_json::Value` tree. If not, we fall back to a custom
`Deserialize` impl that goes through `toml::Value` first.

### 2. `LoadOrInitFile` trait

A trait with one required method and full default implementations:

```rust
pub trait LoadOrInitFile: Sized + for<'de> Deserialize<'de> {
    fn default_content() -> &'static str;

    fn load_or_init(path: &Path) -> Result<Self> { ... }
}
```

The default `load_or_init` implements the shared read → NotFound →
write-default → re-read → parse flow using `toml::from_str::<Self>(source)`
and the merged error variants (below).

Implements:

```rust
impl LoadOrInitFile for ConfigFile {
    fn default_content() -> &'static str { DEFAULT_CONFIG }
}

impl LoadOrInitFile for SecretsFile {
    fn default_content() -> &'static str { DEFAULT_SECRETS }
}
```

### 3. Merge error variants

Replace six specific error variants with three generic ones:

| Remove | Replace with |
|---|---|
| `CouldNotReadConfig` | `CouldNotReadFile` |
| `CouldNotReadSecrets` | `CouldNotReadFile` |
| `CouldNotWriteConfig` | `CouldNotWriteFile` |
| `CouldNotWriteSecrets` | `CouldNotWriteFile` |
| `CouldNotParseSecrets` | `ConfigParse` (already generic, takes path + source + toml error) |

`ConfigParse` already has the nice miette span rendering and `#[error(transparent)]` / `#[diagnostic(transparent)]`. Using it for secrets parse errors is a strict improvement over `CouldNotParseSecrets` which took a `Box<dyn Error>`.

Corresponding helper methods on `Error`:

- `could_not_read_file(path, io_error) -> Self`
- `could_not_write_file(path, io_error) -> Self`
- `config_parse(path, source, &toml_error) -> Self` (already exists)

### 4. Shared `write_default` function

Extract the create-parent-dir → write → log pattern into a single function:

```rust
fn write_default(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::could_not_write_file(path.to_path_buf(), e))?;
    }
    fs::write(path, content)
        .map_err(|e| Error::could_not_write_file(path.to_path_buf(), e))?;
    debug!("redoubtful: wrote default file to {}", path.display());
    Ok(())
}
```

### 5. Callers

After the refactor:

- `ConfigFile::finalize_config_with_cli` calls `ConfigFile::load_or_init(&cfg_path)`.
- `ResolveContext::new()` calls `SecretsFile::load_or_init(&cfg_path)` and wraps the result in a newtype or converts via `.0`.

### What moves where

- **`src/config/config_file.rs`**: Keep `ConfigFile`, `DEFAULT_CONFIG`,
  `resolve_uses`, `parse_config` (for tests). Add the `LoadOrInitFile`
  trait, `write_default` helper, and the `ConfigFile` impl.
- **`src/config/resolve_context.rs`**: Add `SecretsFile`, `DEFAULT_SECRETS`
  const, and the `LoadOrInitFile` impl. Remove `load_or_init_secrets`,
  `init_default_secrets`, and `toml_to_json` (if `serde_json::Value`
  deserializes directly from TOML).

### What stays the same

- `ResolveContext` struct and its `Handlebars` / `render_template` logic.
- `ConfigFile::finalize_config_with_cli` pipeline (just calls the trait method instead of its own `load_or_init`).
- Test structure in `config_file.rs`.
