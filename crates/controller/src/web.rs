//! Serves the web UI built from `web/` (`npm run build` writes `web/dist`).
//!
//! Release builds embed the files; debug builds read them from disk, so a UI
//! rebuild shows up without recompiling the controller.

use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Assets;

pub async fn handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "unknown API route").into_response();
    }
    if let Some(file) = Assets::get(path).filter(|_| !path.is_empty()) {
        // Vite fingerprints everything under assets/, so it can be cached forever.
        let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
        return ([(header::CONTENT_TYPE, file.metadata.mimetype().to_string()), (header::CACHE_CONTROL, cache.to_string())], file.data)
            .into_response();
    }
    // A chunk of another build (a tab opened before an upgrade): a 404, not the
    // app shell, so the page's import fails cleanly and it reloads.
    if path.starts_with("assets/") {
        return (StatusCode::NOT_FOUND, "no such asset").into_response();
    }
    // Client-side routes (e.g. /clients/aa:bb:...) all get the app shell.
    match Assets::get("index.html") {
        Some(index) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], index.data).into_response(),
        None => (StatusCode::NOT_FOUND, "web UI not built: run `npm run build` in web/").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_assets_are_not_the_app_shell() {
        let r = handler(Uri::from_static("/assets/index-0000dead.js")).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
