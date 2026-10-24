use crate::engine::{decimals_for, invoice_json, ticker_for, Engine};
use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use wallet_core::parse_amount;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
}

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/api/create/{currency}", post(create))
        .route("/api/status/{id}", get(status))
        .route("/api/payend/{id}", post(payend))
        .route("/health", get(health))
        .with_state(AppState { engine })
}

async fn health(State(state): State<AppState>) -> Response {
    let ok = state.engine.healthy();
    (
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(serde_json::json!({"ok": ok})),
    )
        .into_response()
}

fn api_key<'a>(headers: &'a HeaderMap, query: &'a StatusQuery) -> Option<&'a str> {
    if let Some(value) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(value);
    }
    if let Some(value) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        return value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "));
    }
    query.api_key.as_deref()
}

#[derive(Debug, Deserialize)]
pub struct CreateQuery {
    pub amount: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub api_key: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    Path(currency): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CreateQuery>,
) -> Response {
    let auth = StatusQuery {
        api_key: query.api_key.clone(),
    };
    if !state.engine.check_api_key(api_key(&headers, &auth)) {
        return err(StatusCode::UNAUTHORIZED, "invalid api key");
    }
    let currency = currency.to_ascii_lowercase();
    let expected = match query.amount.as_deref() {
        None => None,
        Some(text) => match parse_amount(text, decimals_for(&currency)) {
            Ok(value) if value > 0 => Some(value),
            Ok(_) => return err(StatusCode::BAD_REQUEST, "amount must be positive"),
            Err(error) => return err(StatusCode::BAD_REQUEST, &format!("{error:#}")),
        },
    };
    let result =
        tokio::task::spawn_blocking(move || state.engine.create_invoice(&currency, expected)).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invoice worker failed"),
    };
    match result {
        Ok(invoice) => (
            StatusCode::CREATED,
            Json(invoice_json(
                &invoice,
                decimals_for(&invoice.currency),
                ticker_for(&invoice.currency),
            )),
        )
            .into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, &format!("{error:#}")),
    }
}

async fn status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    if !state.engine.check_api_key(api_key(&headers, &query)) {
        return err(StatusCode::UNAUTHORIZED, "invalid api key");
    }
    match state.engine.status(&id) {
        Ok(invoice) => Json(invoice_json(
            &invoice,
            decimals_for(&invoice.currency),
            ticker_for(&invoice.currency),
        ))
        .into_response(),
        Err(error) => err(StatusCode::NOT_FOUND, &format!("{error:#}")),
    }
}

async fn payend(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    if !state.engine.check_api_key(api_key(&headers, &query)) {
        return err(StatusCode::UNAUTHORIZED, "invalid api key");
    }
    let result = tokio::task::spawn_blocking(move || state.engine.payend(&id)).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "invoice worker failed"),
    };
    match result {
        Ok(invoice) => Json(invoice_json(
            &invoice,
            decimals_for(&invoice.currency),
            ticker_for(&invoice.currency),
        ))
        .into_response(),
        Err(error) => {
            let message = format!("{error:#}");
            let status = if message.contains("Unknown invoice") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::BAD_REQUEST
            };
            err(status, &message)
        }
    }
}

fn err(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    async fn request(
        app: Router,
        method: &str,
        path: &str,
        key: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(key) = key {
            request = request.header("X-Api-Key", key);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let code = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (code, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn http_auth_large_eth_amounts_idempotent_close_and_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(crate::engine::tests::config(dir.path())).unwrap();
        let app = router(Arc::clone(&engine));
        let (code, _) = request(app.clone(), "POST", "/api/create/eth?amount=20", None).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, invoice) = request(
            app.clone(),
            "POST",
            "/api/create/eth?amount=20",
            Some("test-api-key"),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(invoice["expected_amount_raw"], "20000000000000000000");
        assert_eq!(invoice["payment_complete"], false);
        let path = format!("/api/payend/{}", invoice["id"].as_str().unwrap());
        for _ in 0..2 {
            let (code, invoice) = request(app.clone(), "POST", &path, Some("test-api-key")).await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(invoice["window_closed"], true);
        }
        let (code, _) = request(
            app.clone(),
            "GET",
            "/api/status/unknown",
            Some("test-api-key"),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        engine.stop(); // also drops Ethereum's nested runtime safely
        let (code, health) = request(app, "GET", "/health", None).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(health["ok"], false);
    }
}
