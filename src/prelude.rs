//! Common imports used across the crate.
//!
//! Every module should start with `use crate::prelude::*;` to get the
//! standard error-handling and logging vocabulary.

// A prelude re-exports items for convenience; it is fine for individual
// consumers to use only a subset.
#![allow(unused_imports)]

pub use miette::{IntoDiagnostic, WrapErr, miette};
pub use tracing::{debug, error, info, instrument, trace, warn};

pub use crate::errors::{Error, Result};
