//! Credential-injection request rewriting.
//!
//! [`Rewrite`] packages the messy "put headers / query params / auth into
//! a request" work out of the proxy handler, so the URI normalization is
//! one self-contained, exhaustively-tested module. The handler builds a
//! [`Rewrite`] from a resolved [`Proxy`] (Step 3 of Phase 4.1) and calls
//! [`Rewrite::apply`] on each request to an injection-configured host.
//!
//! Injected values are [`Secret`]s, whose `Debug`/`Display`/`Serialize`
//! redact — so this module never emits them to logs.

use std::collections::BTreeMap;

use hudsucker::{
    Body,
    hyper::{self, Request},
};
use url::{Position, Url};

use crate::config::{Secret, proxy::ProxyAuth};

/// A proxy's credential-injection config, ready to apply to a request.
///
/// Built from a resolved [`Proxy`]; fields re-use the redacting [`Secret`]
/// type so `Debug`/`Display`/`Serialize` never leak values.
#[derive(Debug, Clone)]
pub struct Rewrite {
    headers: BTreeMap<String, Secret>,
    params: BTreeMap<String, Secret>,
    auth: Option<ProxyAuth>,
}

impl Rewrite {
    /// Build from a `Proxy` if it carries anything to inject, else `None`.
    pub fn from_proxy(p: &crate::config::proxy::Proxy) -> Option<Self> {
        if !p.has_injection() {
            return None;
        }
        Some(Self {
            headers: p.headers.clone(),
            params: p.params.clone(),
            auth: p.auth.clone(),
        })
    }

    /// Apply headers, query params, and auth to `req`, mutating it in place.
    ///
    /// `Body` is [`hudsucker::hyper::Body`]: the request body and its
    /// upgrade state are preserved — only its headers, URI, and auth are
    /// rewritten.
    ///
    /// Idempotent-friendly: headers overwrite (`set` beats existing), query
    /// params merge with the injected value winning per key, and auth sets a
    /// single `Authorization` header. A host is never rewritten twice in one
    /// pass.
    pub fn apply(&self, req: &mut Request<Body>) {
        inject_headers(&self.headers, req);
        merge_query_params(&self.params, req.uri_mut());
        if let Some(auth) = &self.auth {
            inject_auth(auth, req);
        }
    }
}

/// Set each configured header on the request, overwriting any existing value.
fn inject_headers(headers: &BTreeMap<String, Secret>, req: &mut Request<Body>) {
    for (name, value) in headers {
        let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes())
        else {
            continue;
        };
        let Ok(value) = hyper::header::HeaderValue::from_str(&value.0) else {
            continue;
        };
        req.headers_mut().insert(name, value);
    }
}

/// Append `params` to the request URI's query, preserving any existing
/// query and letting the injected value win per key.
///
/// Handles both absolute-form (`http://host/path?q`) and the rare
/// origin-form (`/path?q`) URIs: the query merging happens through
/// [`Url`], then the rebuilt path+query is written back while the rest of
/// the original URI parts are preserved.
fn merge_query_params(params: &BTreeMap<String, Secret>, uri: &mut hyper::Uri) {
    let s = uri.to_string();
    let is_absolute = uri.scheme_str().is_some() && uri.authority().is_some();

    // Normalize the URI to a `Url` we can append pairs to. Absolute-form
    // URIs parse directly; origin-form URIs get a synthetic origin that we
    // discard on write-back (we only extract the path+query span).
    let mut url = if is_absolute {
        match Url::parse(&s) {
            Ok(u) => u,
            Err(_) => return, // unparseable: leave the URI untouched
        }
    } else {
        match Url::parse(&format!("http://sandbox.invalid{s}")) {
            Ok(u) => u,
            Err(_) => return,
        }
    };

    for (key, secret) in params {
        url.query_pairs_mut().append_pair(key, &secret.0);
    }

    // Rebuild only the path-and-query; keep the original scheme/authority
    // (for absolute-form) or absence thereof (for origin-form). Parse the
    // path-and-query span directly into an owned `PathAndQuery` so there's
    // no borrow hanging off the `Url`.
    let path_and_query = &url[Position::BeforePath..];
    let Ok(new_path_and_query) = path_and_query.parse::<hyper::Uri>() else {
        return; // invalid query produced: leave untouched
    };
    let new_path_and_query = new_path_and_query.path_and_query().cloned(); // owned copy

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = new_path_and_query;
    if let Ok(new_uri) = hyper::Uri::from_parts(parts) {
        *uri = new_uri;
    }
}

/// Set a single `Authorization` header from the auth config.
fn inject_auth(auth: &ProxyAuth, req: &mut Request<Body>) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let value = match auth {
        ProxyAuth::Basic { username, password } => {
            let creds = format!("{}:{}", username.0, password.0);
            format!("Basic {}", STANDARD.encode(creds.as_bytes()))
        }
        ProxyAuth::Bearer { token } => format!("Bearer {}", token.0),
    };

    if let Ok(value) = hyper::header::HeaderValue::from_str(&value) {
        req.headers_mut()
            .insert(hyper::header::AUTHORIZATION, value);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{Secret, proxy::ProxyAuth};

    fn req(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request builds")
    }

    fn rewrite(
        headers: BTreeMap<String, Secret>,
        params: BTreeMap<String, Secret>,
        auth: Option<ProxyAuth>,
    ) -> Rewrite {
        Rewrite {
            headers,
            params,
            auth,
        }
    }

    // ===== from_proxy =====

    fn proxy() -> crate::config::proxy::Proxy {
        crate::config::proxy::Proxy {
            host: "example.net".parse().expect("host"),
            port: 443,
            action: crate::config::proxy::ProxyAction::Allow,
            headers: BTreeMap::new(),
            params: BTreeMap::new(),
            auth: None,
        }
    }

    #[test]
    fn from_proxy_none_when_blank() {
        assert!(Rewrite::from_proxy(&proxy()).is_none());
    }

    #[test]
    fn from_proxy_some_when_headers_present() {
        let mut p = proxy();
        p.headers
            .insert("X-Test".to_string(), Secret("value".to_string()));
        assert!(Rewrite::from_proxy(&p).is_some());
    }

    // ===== inject_headers =====

    #[test]
    fn inject_headers_sets_each_header() {
        let mut headers = BTreeMap::new();
        headers.insert("X-A".to_string(), Secret("1".to_string()));
        headers.insert("X-B".to_string(), Secret("2".to_string()));
        let r = rewrite(headers, BTreeMap::new(), None);
        let mut request = req("http://example.net/");
        r.apply(&mut request);
        assert_eq!(request.headers()["x-a"], "1");
        assert_eq!(request.headers()["x-b"], "2");
    }

    #[test]
    fn inject_headers_overwrites_existing() {
        let mut headers = BTreeMap::new();
        headers.insert("X-A".to_string(), Secret("new".to_string()));
        let r = rewrite(headers, BTreeMap::new(), None);
        let mut request = req("http://example.net/");
        request
            .headers_mut()
            .insert("x-a", hyper::header::HeaderValue::from_static("old"));
        r.apply(&mut request);
        assert_eq!(request.headers()["x-a"], "new");
    }

    // ===== merge_query_params =====

    #[test]
    fn inject_params_merges_preserving_existing() {
        let mut params = BTreeMap::new();
        params.insert("b".to_string(), Secret("2".to_string()));
        let r = rewrite(BTreeMap::new(), params, None);
        let mut request = req("http://example.net/path?a=1");
        r.apply(&mut request);
        let q = request.uri().query().expect("query present");
        // Order isn't guaranteed by BTreeMap insertion; check both keys.
        assert!(q.contains("a=1"), "existing param preserved: {q}");
        assert!(q.contains("b=2"), "new param added: {q}");
    }

    #[test]
    fn inject_params_encodes_special_chars() {
        let mut params = BTreeMap::new();
        params.insert("k".to_string(), Secret("a b&c=d".to_string()));
        let r = rewrite(BTreeMap::new(), params, None);
        let mut request = req("http://example.net/");
        r.apply(&mut request);
        let q = request.uri().query().expect("query present");
        // Delimiters (&, =) inside the value must be percent-encoded so
        // they don't corrupt the query structure. The `url` crate
        // form-encodes a space as `+` (valid `x-www-form-urlencoded`).
        assert!(!q.contains(' '), "space must be encoded: {q}");
        assert_eq!(q, "k=a+b%26c%3Dd");
    }

    #[test]
    fn inject_params_origin_form() {
        let mut params = BTreeMap::new();
        params.insert("x".to_string(), Secret("1".to_string()));
        let r = rewrite(BTreeMap::new(), params, None);
        let mut request = req("/path");
        assert!(request.uri().authority().is_none());
        r.apply(&mut request);
        assert_eq!(request.uri().query(), Some("x=1"));
        // Origin-form stays origin-form: no scheme/authority added.
        assert!(request.uri().scheme_str().is_none());
        assert!(request.uri().authority().is_none());
        assert_eq!(request.uri().path(), "/path");
    }

    // ===== inject_auth =====

    #[test]
    fn inject_auth_basic() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let auth = ProxyAuth::Basic {
            username: Secret("user".to_string()),
            password: Secret("pass".to_string()),
        };
        let r = rewrite(BTreeMap::new(), BTreeMap::new(), Some(auth));
        let mut request = req("http://example.net/");
        r.apply(&mut request);
        let expected =
            format!("Basic {}", STANDARD.encode("user:pass".as_bytes()));
        assert_eq!(request.headers()[hyper::header::AUTHORIZATION], expected);
    }

    #[test]
    fn inject_auth_bearer() {
        let auth = ProxyAuth::Bearer {
            token: Secret("tok123".to_string()),
        };
        let r = rewrite(BTreeMap::new(), BTreeMap::new(), Some(auth));
        let mut request = req("http://example.net/");
        r.apply(&mut request);
        assert_eq!(
            request.headers()[hyper::header::AUTHORIZATION],
            "Bearer tok123"
        );
    }

    // ===== noop =====

    #[test]
    fn apply_injection_noop_with_blank_config() {
        // A blank Rewrite shouldn't exist via from_proxy, but apply must be
        // safe on one: nothing changes.
        let r = rewrite(BTreeMap::new(), BTreeMap::new(), None);
        let mut request = req("http://example.net/?a=1");
        request
            .headers_mut()
            .insert("x-k", hyper::header::HeaderValue::from_static("keep"));
        r.apply(&mut request);
        assert_eq!(request.uri().query(), Some("a=1"));
        assert_eq!(request.headers()["x-k"], "keep");
        assert!(
            request
                .headers()
                .get(hyper::header::AUTHORIZATION)
                .is_none()
        );
    }
}
