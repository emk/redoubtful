//! Hostname normalization for proxy configuration.

/// Normalize a hostname for use as a proxy key.
///
/// Currently just lowercases the string. Extensible for future
/// security-related normalization (IDN punycode, trailing dots,
/// etc.) without changing the public API or all call sites.
pub fn normalize_hostname(host: &str) -> String {
    host.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lowercase() {
        assert_eq!(normalize_hostname("Example.Net"), "example.net");
    }

    #[test]
    fn normalize_already_lowercase() {
        assert_eq!(normalize_hostname("example.net"), "example.net");
    }

    #[test]
    fn normalize_mixed_case() {
        assert_eq!(normalize_hostname("GITHUB.COM"), "github.com");
    }
}
