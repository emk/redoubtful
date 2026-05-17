//! Canonicalized hostname type.
//!
//! A [`Hostname`] is a normalized (lowercased, non-empty) hostname
//! suitable for use as a proxy key and for cheap case-insensitive
//! comparisons. Normalization happens at construction via [`FromStr`]
//! or [`Deserialize`], so callers always hold a canonical value.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::prelude::*;

/// A canonicalized hostname.
///
/// Stored in lowercase so comparison is case-insensitive by default.
/// Validated at construction: rejects empty strings.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Create a new `Hostname` from a string, normalizing to lowercase.
    ///
    /// Rejects empty strings.
    pub fn new(s: &str) -> Result<Self> {
        let normalized = s.to_lowercase();
        if normalized.is_empty() {
            return Err(Error::ProxyEmptyHost);
        }
        Ok(Self(normalized))
    }
}

impl FromStr for Hostname {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for Hostname {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hostname {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== new / FromStr =====

    #[test]
    fn new_lowercases() {
        let h = Hostname::new("Example.Net").expect("parses");
        assert_eq!(h.as_ref(), "example.net");
    }

    #[test]
    fn new_already_lowercase() {
        let h = Hostname::new("example.net").expect("parses");
        assert_eq!(h.as_ref(), "example.net");
    }

    #[test]
    fn new_rejects_empty() {
        let err = Hostname::new("").expect_err("empty must error");
        assert!(matches!(err, Error::ProxyEmptyHost));
    }

    #[test]
    fn fromstr_delegates_to_new() {
        let h: Hostname = "GITHUB.COM".parse().expect("parses");
        assert_eq!(h.as_ref(), "github.com");
    }

    // ===== Display =====

    #[test]
    fn display_shows_normalized() {
        let h: Hostname = "Example.Net".parse().expect("parses");
        assert_eq!(format!("{}", h), "example.net");
    }

    // ===== Serialize / Deserialize =====

    #[test]
    fn serialize_roundtrip() {
        let h: Hostname = "Example.Net".parse().expect("parses");
        let json = serde_json::to_string(&h).expect("serializes");
        assert_eq!(json, "\"example.net\"");
        let h2: Hostname = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(h, h2);
    }

    #[test]
    fn deserialize_normalizes() {
        let h: Hostname =
            serde_json::from_str("\"EXAMPLE.COM\"").expect("deserializes");
        assert_eq!(h.as_ref(), "example.com");
    }

    #[test]
    fn deserialize_rejects_empty() {
        let result = serde_json::from_str::<Hostname>("\"\"");
        assert!(result.is_err());
    }

    // ===== Ord / Eq =====

    #[test]
    fn ord_is_case_insensitive() {
        let a: Hostname = "Example.Net".parse().expect("parses");
        let b: Hostname = "example.net".parse().expect("parses");
        assert_eq!(a, b, "normalized forms must be equal");
    }
}
