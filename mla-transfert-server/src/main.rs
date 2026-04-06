mod config;
mod state;

use axum::{Router, routing::get};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use config::ServerConfig;
use state::AppState;

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = ServerConfig::default();

    tokio::fs::create_dir_all(&config.storage_dir)
        .await
        .expect("Failed to create storage directory");

    let state = AppState::new(config.storage_dir, config.max_file_size);

    let app = Router::new()
        .route("/api/health", get(health))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}
