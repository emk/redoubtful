//! Resolution context for [`Decl::resolve`] calls.
//!
//! Holds a pre-warmed [`handlebars::Handlebars`] registry seeded with
//! secrets loaded from `~/.config/redoubtful/secrets.toml`. Template
//! rendering during `ProxyDecl::resolve` (and any other future Decl
//! that needs credentials) goes through [`ResolveContext::render_template`].
//!
//! Secrets auto-init uses the shared [`LoadOrInitFile`] trait: on first run
//! the embedded [`DEFAULT_SECRETS`] is written to disk and re-read.
//! Unlike `config.toml`, secrets are *not* profile-scoped — they are
//! a single free-form TOML table consumed by any proxy declaration
//! anywhere.
//!
//! Strict mode is enabled on the Handlebars registry so that accessing
//! an undefined variable (e.g. `{{secrets.foo.bar}}` where the path
//! doesn't exist) raises a `RenderError` instead of silently rendering
//! an empty string.

use std::collections::HashMap;

use handlebars::Handlebars;
use serde::Deserialize;

use crate::config::config_file::LoadOrInitFile;
use crate::prelude::*;

/// Embedded default-secrets text, dropped onto disk byte-for-byte the
/// first time the secrets file is absent. `include_str!` pulls the
/// file in at compile time.
const DEFAULT_SECRETS: &str = include_str!("../../assets/secrets.toml.default");

/// The path (relative to `~/.config/redoubtful/`) of the secrets file.
const SECRETS_FILENAME: &str = "secrets.toml";

/// Free-form secrets parsed from `secrets.toml`.
///
/// Wraps a [`serde_json::Value`] so it can be consumed by handlebars
/// template rendering. TOML sections like `[example] api-key = "x"`
/// become JSON `{ "example": { "api-key": "x" } }` — handlebars dot-notation
/// (`{{secrets.example.api-key}}`) works natively.
///
/// `#[serde(transparent)]` lets `toml::from_str::<SecretsFile>` deserialize
/// TOML directly into a [`serde_json::Value`] via serde's generic event stream.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretsFile(serde_json::Value);

impl LoadOrInitFile for SecretsFile {
    fn default_content() -> &'static str {
        DEFAULT_SECRETS
    }
}

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
    secrets: serde_json::Value,
}

impl ResolveContext {
    /// Build a context from the XDG secrets file. Loads secrets from
    /// `~/.config/redoubtful/secrets.toml`, auto-initializing the file
    /// if absent.
    pub fn new() -> Result<Self> {
        let cfg_path = xdg::BaseDirectories::with_prefix("redoubtful")
            .get_config_file(SECRETS_FILENAME)
            .ok_or_else(|| Error::missing_env_var("HOME"))?;
        let secrets = SecretsFile::load_or_init(&cfg_path)?.0;
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
            secrets: serde_json::Value::Object(serde_json::Map::new()),
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
