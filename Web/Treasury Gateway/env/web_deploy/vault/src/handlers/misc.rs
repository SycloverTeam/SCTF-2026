use crate::state::AppState;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};

pub async fn index() -> Response {
    Json(serde_json::json!({
        "service": "Treasury Compliance Export",
        "description": "cash-position reconciliation reporting service",
    }))
    .into_response()
}

pub async fn status(State(_state): State<AppState>) -> Response {
    Json(serde_json::json!({
        "service": "Treasury Compliance Export",
        "status": "ok",
    }))
    .into_response()
}

pub async fn internal_export_snapshot(State(_state): State<AppState>) -> Response {
    let reconciliation_token = std::env::var("TREASURY_RECONCILIATION_TOKEN").unwrap();
    let body = format!(
        r#"{{"portfolio":"northwind-capital","report":"daily-cash-reconciliation","generated_at":"2026-06-02T09:30:00+08:00","positions":[{{"desk":"treasury-ops","currency":"USD","notional":18420000}},{{"desk":"fx-liquidity","currency":"EUR","notional":7200000}},{{"desk":"settlement","currency":"JPY","notional":930000000}}],"controls":{{"source":"custody-ledger","approval":"two-person-review"}},"reconciliation_token":"{reconciliation_token}"}}"#
    );
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}
