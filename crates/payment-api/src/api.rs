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
        .route("/health", get(|| async { Json(serde_json::json!({"ok": true})) }))
        .with_state(AppState { engine })
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
    match state.engine.create_invoice(&currency, expected) {
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
    match state.engine.payend(&id) {
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
