//! Serves the web UI built from `web/` (`npm run build` writes `web/dist`).
//!
//! Release builds embed the files; debug builds read them from disk, so a UI
//! rebuild shows up without recompiling the controller.

use std::borrow::Cow;

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Assets;

/// Vite fingerprints everything under assets/, so it can be cached forever.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";
/// The rest (index.html, the icons) is checked again at each use: a 304 then
/// saves sending it again.
const NO_CACHE: &str = "no-cache";
const HTML: &str = "text/html; charset=utf-8";

pub async fn handler(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    // Answered as every API error is, so the UI shows its message.
    if path.starts_with("api/") {
        return crate::api::ApiError(StatusCode::NOT_FOUND, "unknown API route".into()).into_response();
    }
    if let Some(file) = Assets::get(path).filter(|_| !path.is_empty()) {
        let cache = if path.starts_with("assets/") { IMMUTABLE } else { NO_CACHE };
        let mime = HeaderValue::from_str(file.metadata.mimetype()).unwrap_or(HeaderValue::from_static("application/octet-stream"));
        return serve(&headers, file.data, file.metadata.sha256_hash(), mime, cache);
    }
    // A chunk of another build (a tab opened before an upgrade): a 404, not the
    // app shell, so the page's import fails cleanly and it reloads.
    if path.starts_with("assets/") {
        return (StatusCode::NOT_FOUND, "no such asset").into_response();
    }
    // Client-side routes (e.g. /clients/aa:bb:...) all get the app shell.
    match Assets::get("index.html") {
        Some(index) => serve(&headers, index.data, index.metadata.sha256_hash(), HeaderValue::from_static(HTML), NO_CACHE),
        None => (StatusCode::NOT_FOUND, "web UI not built: run `npm run build` in web/").into_response(),
    }
}

/// A file with its ETag (from its SHA-256, which the build embeds), or a 304
/// when the browser's copy (`If-None-Match`) is that one. The tag is weak, as
/// the compression layer may send the file gzipped.
fn serve(headers: &HeaderMap, data: Cow<'static, [u8]>, sha256: [u8; 32], mime: HeaderValue, cache: &'static str) -> Response {
    let cache = HeaderValue::from_static(cache);
    let etag = format!("W/\"{}\"", hex::encode(&sha256[..16]));
    let fresh = headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|t| t == "*" || t.trim_start_matches("W/") == &etag[2..]);
    let etag = HeaderValue::from_str(&etag).expect("hex in quotes");
    if fresh {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag), (header::CACHE_CONTROL, cache)]).into_response();
    }
    ([(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, cache), (header::ETAG, etag)], data).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_assets_are_not_the_app_shell() {
        let r = handler(Uri::from_static("/assets/index-0000dead.js"), HeaderMap::new()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unknown_api_route_is_answered_in_json() {
        let r = handler(Uri::from_static("/api/nope"), HeaderMap::new()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(r.into_body(), 1 << 10).await.unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), serde_json::json!({ "error": "unknown API route" }));
    }

    #[test]
    fn a_file_the_browser_has_is_not_sent_again() {
        let get = |if_none_match: Option<&'static str>| {
            let mut h = HeaderMap::new();
            if let Some(v) = if_none_match {
                h.insert(header::IF_NONE_MATCH, HeaderValue::from_static(v));
            }
            serve(&h, Cow::Borrowed(b"<html>"), [0xab; 32], HeaderValue::from_static(HTML), NO_CACHE)
        };
        let first = get(None);
        assert_eq!(first.status(), StatusCode::OK);
        let etag = first.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(etag, format!("W/\"{}\"", "ab".repeat(16)));
        assert_eq!(first.headers()[header::CACHE_CONTROL], "no-cache");
        // Weak or strong, alone or in a list, it matches.
        for v in ["W/\"abababababababababababababababab\"", "\"abababababababababababababababab\"", "\"x\", W/\"abababababababababababababababab\"", "*"] {
            let r = get(Some(v));
            assert_eq!(r.status(), StatusCode::NOT_MODIFIED, "{v}");
            assert_eq!(r.headers()[header::ETAG], etag.as_str());
        }
        assert_eq!(get(Some("W/\"abab\"")).status(), StatusCode::OK, "another version");
    }
}
