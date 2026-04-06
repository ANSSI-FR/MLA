# MLA-Transfert Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a zero-knowledge relay server in Rust/Axum that stores encrypted MLA blobs temporarily, serves download links, and provides WebRTC signaling for P2P transfers.

**Architecture:** Axum HTTP server with 3 concerns: file upload/download relay with expiration, WebSocket-based WebRTC signaling, and a background purge task. No database -- in-memory index with filesystem storage. The server never sees plaintext or keys.

**Tech Stack:** Rust, Axum, Tokio, tower-http (CORS), uuid, serde/serde_json

---

## File Structure

```
mla-transfert-server/
├── Cargo.toml
├── src/
│   ├── main.rs          # Entry point, router setup, app state
│   ├── config.rs        # Server config (port, storage dir, max file size)
│   ├── relay.rs         # POST /api/upload, GET /api/download/:id, GET /api/info/:id
│   ├── signaling.rs     # GET /api/signal/:room WebSocket handler
│   ├── purge.rs         # Background task to delete expired files
│   └── state.rs         # AppState: in-memory transfer index + storage path
```

**Modifications au workspace:**
- Modify: `Cargo.toml` (root) -- add `mla-transfert-server` to workspace members

---

### Task 1: Scaffold server crate and basic health endpoint

**Files:**
- Modify: `Cargo.toml` (root workspace)
- Create: `mla-transfert-server/Cargo.toml`
- Create: `mla-transfert-server/src/main.rs`
- Create: `mla-transfert-server/src/config.rs`
- Create: `mla-transfert-server/src/state.rs`

- [ ] **Step 1: Add to workspace**

In root `Cargo.toml`, add `"mla-transfert-server"` to members:

```toml
[workspace]
members = [
    "mla",
    "mla-fuzz-afl",
    "mlar",
    "mlar/mlar-upgrader",
    "bindings/C",
    "mla-wasm",
    "mla-transfert-server",
]
```

- [ ] **Step 2: Create mla-transfert-server/Cargo.toml**

```toml
[package]
name = "mla-transfert-server"
version = "0.1.0"
edition = "2024"
license = "LGPL-3.0-only"
description = "Zero-knowledge relay server for MLA-Transfert"
publish = false

[dependencies]
axum = { version = "0.8", features = ["ws", "multipart"] }
tokio = { version = "1", features = ["full"] }
tower-http = { version = "0.6", features = ["cors"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[lints]
workspace = true
```

- [ ] **Step 3: Create config.rs**

```rust
use std::path::PathBuf;

pub struct ServerConfig {
    pub port: u16,
    pub storage_dir: PathBuf,
    pub max_file_size: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 3001,
            storage_dir: PathBuf::from("./data/uploads"),
            max_file_size: 2 * 1024 * 1024 * 1024, // 2 GB
        }
    }
}
```

- [ ] **Step 4: Create state.rs**

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct TransferEntry {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub expires_at: SystemTime,
    pub created_at: SystemTime,
}

#[derive(Clone)]
pub struct AppState {
    pub transfers: Arc<RwLock<HashMap<String, TransferEntry>>>,
    pub storage_dir: PathBuf,
    pub max_file_size: u64,
}

impl AppState {
    pub fn new(storage_dir: PathBuf, max_file_size: u64) -> Self {
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            storage_dir,
            max_file_size,
        }
    }

    pub fn expiration_duration(hours: u64) -> Duration {
        Duration::from_secs(hours * 3600)
    }
}
```

- [ ] **Step 5: Create main.rs with health endpoint**

```rust
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
```

- [ ] **Step 6: Verify compilation**

Run: `cargo check -p mla-transfert-server`
Expected: OK

- [ ] **Step 7: Commit**

```bash
git add mla-transfert-server/ Cargo.toml
git commit -m "feat(server): scaffold Axum server with health endpoint and app state"
```

---

### Task 2: File upload endpoint (POST /api/upload)

**Files:**
- Create: `mla-transfert-server/src/relay.rs`
- Modify: `mla-transfert-server/src/main.rs` (add route)

- [ ] **Step 1: Create relay.rs with upload handler**

```rust
use std::time::SystemTime;

use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::{AppState, TransferEntry};

#[derive(Serialize)]
pub struct UploadResponse {
    pub id: String,
    pub expires_in_hours: u64,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut expires_hours: u64 = 24;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| bad_request(format!("Multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| bad_request(format!("Read error: {e}")))?;

                if data.len() as u64 > state.max_file_size {
                    return Err(bad_request("File too large".to_string()));
                }

                file_data = Some(data.to_vec());
            }
            "expires_hours" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| bad_request(format!("Read error: {e}")))?;
                expires_hours = match text.as_str() {
                    "1" => 1,
                    "24" => 24,
                    "168" => 168,
                    _ => 24,
                };
            }
            _ => {}
        }
    }

    let data = file_data.ok_or_else(|| bad_request("No file provided".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let file_path = state.storage_dir.join(&id);
    tokio::fs::write(&file_path, &data)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: format!("Write error: {e}") })))?;

    let entry = TransferEntry {
        id: id.clone(),
        filename: format!("{id}.mla"),
        size: data.len() as u64,
        expires_at: SystemTime::now() + AppState::expiration_duration(expires_hours),
        created_at: SystemTime::now(),
    };

    state.transfers.write().await.insert(id.clone(), entry);

    Ok(Json(UploadResponse {
        id,
        expires_in_hours: expires_hours,
    }))
}

fn bad_request(msg: String) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg }))
}
```

- [ ] **Step 2: Add download and info handlers**

Append to `relay.rs`:

```rust
use axum::extract::Path;

#[derive(Serialize)]
pub struct TransferInfo {
    pub id: String,
    pub size: u64,
    pub expires_in_seconds: u64,
}

pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let transfers = state.transfers.read().await;
    let entry = transfers.get(&id).ok_or(StatusCode::NOT_FOUND)?;

    if entry.expires_at < SystemTime::now() {
        drop(transfers);
        state.transfers.write().await.remove(&id);
        return Err(StatusCode::GONE);
    }

    let file_path = state.storage_dir.join(&id);
    tokio::fs::read(&file_path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)
}

pub async fn info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<TransferInfo>, StatusCode> {
    let transfers = state.transfers.read().await;
    let entry = transfers.get(&id).ok_or(StatusCode::NOT_FOUND)?;

    if entry.expires_at < SystemTime::now() {
        return Err(StatusCode::GONE);
    }

    let expires_in = entry
        .expires_at
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();

    Ok(Json(TransferInfo {
        id: entry.id.clone(),
        size: entry.size,
        expires_in_seconds: expires_in,
    }))
}
```

- [ ] **Step 3: Wire routes in main.rs**

Update `main.rs`:

```rust
mod config;
mod relay;
mod state;

use axum::{Router, routing::{get, post}};
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
        .route("/api/upload", post(relay::upload))
        .route("/api/download/{id}", get(relay::download))
        .route("/api/info/{id}", get(relay::info))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Server listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p mla-transfert-server`
Expected: OK

- [ ] **Step 5: Manual smoke test**

Run in terminal 1:
```bash
cargo run -p mla-transfert-server
```

Run in terminal 2:
```bash
# Health check
curl http://localhost:3001/api/health
# Expected: ok

# Upload a test file
echo "test data" > /tmp/test.mla
curl -X POST http://localhost:3001/api/upload -F "file=@/tmp/test.mla" -F "expires_hours=1"
# Expected: {"id":"<uuid>","expires_in_hours":1}

# Download using the returned ID
curl http://localhost:3001/api/download/<uuid>
# Expected: test data

# Info
curl http://localhost:3001/api/info/<uuid>
# Expected: {"id":"<uuid>","size":10,"expires_in_seconds":...}
```

- [ ] **Step 6: Commit**

```bash
git add mla-transfert-server/src/
git commit -m "feat(server): add upload/download/info relay endpoints"
```

---

### Task 3: Background purge task

**Files:**
- Create: `mla-transfert-server/src/purge.rs`
- Modify: `mla-transfert-server/src/main.rs` (spawn purge task)

- [ ] **Step 1: Create purge.rs**

```rust
use std::time::{Duration, SystemTime};

use crate::state::AppState;

pub fn spawn_purge_task(state: AppState) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(60);
        loop {
            tokio::time::sleep(interval).await;
            purge_expired(&state).await;
        }
    });
}

async fn purge_expired(state: &AppState) {
    let now = SystemTime::now();
    let mut transfers = state.transfers.write().await;

    let expired_ids: Vec<String> = transfers
        .iter()
        .filter(|(_, entry)| entry.expires_at < now)
        .map(|(id, _)| id.clone())
        .collect();

    for id in &expired_ids {
        transfers.remove(id);
        let file_path = state.storage_dir.join(id);
        if let Err(e) = tokio::fs::remove_file(&file_path).await {
            tracing::warn!("Failed to delete expired file {id}: {e}");
        } else {
            tracing::info!("Purged expired transfer {id}");
        }
    }
}
```

- [ ] **Step 2: Spawn purge task in main.rs**

Add `mod purge;` and spawn before starting the server:

```rust
mod config;
mod purge;
mod relay;
mod state;

// ... in main(), after creating state, before building app:
    purge::spawn_purge_task(state.clone());
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p mla-transfert-server`
Expected: OK

- [ ] **Step 4: Commit**

```bash
git add mla-transfert-server/src/
git commit -m "feat(server): add background purge task for expired transfers"
```

---

### Task 4: WebRTC signaling via WebSocket

**Files:**
- Create: `mla-transfert-server/src/signaling.rs`
- Modify: `mla-transfert-server/src/main.rs` (add route)
- Modify: `mla-transfert-server/src/state.rs` (add rooms)

- [ ] **Step 1: Add signaling rooms to state.rs**

Add to `AppState`:

```rust
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub transfers: Arc<RwLock<HashMap<String, TransferEntry>>>,
    pub signal_rooms: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
    pub storage_dir: PathBuf,
    pub max_file_size: u64,
}

impl AppState {
    pub fn new(storage_dir: PathBuf, max_file_size: u64) -> Self {
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            signal_rooms: Arc::new(RwLock::new(HashMap::new())),
            storage_dir,
            max_file_size,
        }
    }

    pub fn expiration_duration(hours: u64) -> Duration {
        Duration::from_secs(hours * 3600)
    }
}
```

- [ ] **Step 2: Create signaling.rs**

```rust
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::Response;
use tokio::sync::broadcast;

use crate::state::AppState;

const ROOM_CAPACITY: usize = 16;

pub async fn signal(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(room): Path<String>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, room))
}

async fn handle_socket(socket: WebSocket, state: AppState, room: String) {
    let tx = {
        let mut rooms = state.signal_rooms.write().await;
        rooms
            .entry(room.clone())
            .or_insert_with(|| broadcast::channel(ROOM_CAPACITY).0)
            .clone()
    };

    let mut rx = tx.subscribe();

    let (mut ws_sender, mut ws_receiver) = socket.split();

    use futures_util::{SinkExt, StreamExt};

    let tx_clone = tx.clone();
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender
                .send(Message::Text(msg.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_receiver.next().await {
            if let Message::Text(text) = msg {
                let _ = tx_clone.send(text.to_string());
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    // Clean up empty rooms
    let rooms = state.signal_rooms.read().await;
    if let Some(sender) = rooms.get(&room) {
        if sender.receiver_count() == 0 {
            drop(rooms);
            state.signal_rooms.write().await.remove(&room);
        }
    }
}
```

- [ ] **Step 3: Add futures-util dependency**

Add to `mla-transfert-server/Cargo.toml`:

```toml
futures-util = "0.3"
```

- [ ] **Step 4: Wire signaling route in main.rs**

Add `mod signaling;` and the route:

```rust
mod config;
mod purge;
mod relay;
mod signaling;
mod state;

// ... in the router:
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/upload", post(relay::upload))
        .route("/api/download/{id}", get(relay::download))
        .route("/api/info/{id}", get(relay::info))
        .route("/api/signal/{room}", get(signaling::signal))
        .layer(CorsLayer::permissive())
        .with_state(state);
```

- [ ] **Step 5: Verify compilation**

Run: `cargo check -p mla-transfert-server`
Expected: OK

- [ ] **Step 6: Commit**

```bash
git add mla-transfert-server/
git commit -m "feat(server): add WebRTC signaling via WebSocket rooms"
```

---

## API Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/upload` | Upload encrypted .mla (multipart: file + expires_hours) |
| GET | `/api/download/{id}` | Download encrypted .mla by ID |
| GET | `/api/info/{id}` | Get transfer metadata (size, expiration) |
| GET | `/api/signal/{room}` | WebSocket signaling for WebRTC P2P |
