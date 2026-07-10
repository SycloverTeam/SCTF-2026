use crate::{handlers::misc, state::AppState};
use axum::{routing::get, Router};

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", get(misc::index))
        .route("/api/status", get(misc::status))
        .route(
            "/internal/compliance/export-snapshot",
            get(misc::internal_export_snapshot),
        )
        .with_state(state)
}
