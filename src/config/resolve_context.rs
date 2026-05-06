//! Resolution context for [`Decl::resolve`] calls.
//!
//! Holds a pre-warmed [`handlebars::Handlebars`] registry seeded with
//! secrets loaded from `~/.config/redoubtful/secrets.toml`. Template
//! rendering during `ProxyDecl::resolve` (and any other future Decl
//! that needs credentials) goes through [`ResolveContext::render_template`].
//!
//! Secrets auto-init mirrors the `config.toml` pattern: on first run
//! the embedded [`DEFAULT_SECRETS`] is written to disk and re-read.
//! Unlike `config.toml`, secrets are *not* profile-scoped — they are
//! a single free-form TOML table consumed by any proxy declaration
//! anywhere.
//!
//! Strict mode is enabled on the Handlebars registry so that accessing
//! an undefined variable (e.g. `{{secrets.foo.bar}}` where the path
//! doesn't exist) raises a `RenderError` instead of silently rendering
//! an empty string.

use std::{collections::HashMap, fs, io, path::Path};

use handlebars::Handlebars;
use serde_json::Value;

use crate::prelude::*;

/// Embedded default-secrets text, dropped onto disk byte-for-byte the
/// first time the secrets file is absent. `include_str!` pulls the
/// file in at compile time.
const DEFAULT_SECRETS: &str = include_str!("../../assets/secrets.toml.default");

/// The path (relative to `~/.config/redoubtful/`) of the secrets file.
const SECRETS_FILENAME: &str = "secrets.toml";

/// Context for resolving declared configuration.
///
/// Carries a pre-warmed [`handlebars::Handlebars`] registry and the
/// secrets JSON value. During [`crate::config::Decl::resolve`], proxy
/// declarations (and any other template-bearing types) render their
/// Handlebars templates against the secrets and get plain `String`
/// values back.
#[allow(dead_code)]
pub struct ResolveContext {
    #[allow(dead_code)]
    registry: Handlebars<'static>,
    #[allow(dead_code)]
    secrets: Value,
}

impl ResolveContext {
    /// Build a context from the XDG secrets file. Loads secrets from
    /// `~/.config/redoubtful/secrets.toml`, auto-initializing the file
    /// if absent.
    pub fn new() -> Result<Self> {
        let cfg_path = xdg::BaseDirectories::with_prefix("redoubtful")
            .get_config_file(SECRETS_FILENAME)
            .ok_or_else(|| Error::missing_env_var("HOME"))?;
        let secrets = load_or_init_secrets(&cfg_path)?;
        let mut registry = Handlebars::new();
        registry.set_strict_mode(true);
        Ok(Self { registry, secrets })
    }

    /// Build an empty context with zero secrets. Used by tests that
    /// don't exercise template rendering.
    #[allow(dead_code)]
    pub fn empty() -> Self {
        let mut registry = Handlebars::new();
        registry.set_strict_mode(true);
        Self {
            registry,
            secrets: Value::Object(serde_json::Map::new()),
        }
    }

    /// Render a Handlebars template string against the secrets.
    ///
    /// Returns an [`Error::TemplateRender`] if the template references
    /// an undefined variable (strict mode catches this) or on other
    /// rendering failures.
    #[allow(dead_code)]
    pub fn render_template(&self, template: &str) -> Result<String> {
        let mut ctx = HashMap::new();
        ctx.insert("secrets".to_owned(), self.secrets.clone());
        self.registry
            .render_template(template, &ctx)
            .map_err(|e| Error::template_render(e.to_string()))
    }
}

/// Load the secrets file, auto-initializing on first run.
///
/// Parses as `toml::Value` (free-form) and converts to
/// `serde_json::Value` that handlebars can consume.
fn load_or_init_secrets(path: &Path) -> Result<Value> {
    match fs::read_to_string(path) {
        Ok(source) => {
            let value: toml::Value = toml::from_str(&source).map_err(|e| {
                Error::could_not_parse_secrets(path.to_path_buf(), Box::new(e))
            })?;
            Ok(toml_to_json(&value))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            init_default_secrets(path)?;
            let source = fs::read_to_string(path).map_err(|e| {
                Error::could_not_read_secrets(path.to_path_buf(), e)
            })?;
            let value: toml::Value = toml::from_str(&source).map_err(|e| {
                Error::could_not_parse_secrets(path.to_path_buf(), Box::new(e))
            })?;
            Ok(toml_to_json(&value))
        }
        Err(e) => Err(Error::could_not_read_secrets(path.to_path_buf(), e)),
    }
}

/// Write the embedded default secrets to `path`, creating parent dirs
/// as needed.
fn init_default_secrets(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::could_not_write_secrets(path.to_path_buf(), e)
        })?;
    }
    fs::write(path, DEFAULT_SECRETS)
        .map_err(|e| Error::could_not_write_secrets(path.to_path_buf(), e))?;
    debug!("redoubtful: wrote default secrets to {}", path.display());
    Ok(())
}

/// Convert a `toml::Value` to a `serde_json::Value`.
///
/// TOML sections like `[example] api-key = "x"` become JSON
/// `{ "example": { "api-key": "x" } }` — handlebars dot-notation
/// (`{{secrets.example.api-key}}`) works natively.
fn toml_to_json(value: &toml::Value) -> Value {
    match value {
        toml::Value::Boolean(b) => Value::Bool(*b),
        toml::Value::Integer(i) => Value::Number((*i).into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml::Value::String(s) => Value::String(s.clone()),
        toml::Value::Array(arr) => {
            Value::Array(arr.iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let map = table
                .iter()
                .map(|(k, v)| (k.clone(), toml_to_json(v)))
                .collect();
            Value::Object(map)
        }
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
    }
}
