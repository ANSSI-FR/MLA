mod config;
mod purge;
mod relay;
mod signaling;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_http::cors::{AllowOrigin, CorsLayer};
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

    purge::spawn_purge_task(state.clone());

    // Rate limiter: 20 req/s refill, burst of 40 — protects against floods
    // while staying transparent for normal interactive use.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(20)
            .burst_size(40)
            .use_headers()
            .key_extractor(PeerIpKeyExtractor)
            .finish()
            .expect("valid governor config"),
    );

    let allowed_origin =
        std::env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| "http://localhost:4321".to_string());
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            HeaderValue::from_str(&allowed_origin)
                .expect("ALLOWED_ORIGIN is not a valid HTTP header value"),
        ))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/upload", post(relay::upload))
        .route("/api/download/{id}", get(relay::download))
        .route("/api/info/{id}", get(relay::info))
        .route("/api/signal/{room}", get(signaling::signal))
        .layer(DefaultBodyLimit::max(
            state.max_file_size.try_into().unwrap_or(usize::MAX),
        ))
        .layer(cors)
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Server error");
}
