use std::time::SystemTime;

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use serde_json::json;

/// Helper : retourne toujours une erreur JSON `{"error": "..."}`.
fn json_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({ "error": msg.into() })))
}

type JsonError = (StatusCode, Json<serde_json::Value>);

use crate::state::AppState;

#[derive(Serialize)]
pub struct UploadResponse {
    id: String,
    expires_in_hours: u64,
}

#[derive(Serialize)]
pub struct InfoResponse {
    id: String,
    size: u64,
    expires_in_seconds: u64,
}

/// POST /api/upload
///
/// Accepts a multipart form with `file` (binary) and optional `expires_hours` (text).
pub async fn upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, JsonError> {
    let mut file_data: Option<(String, Vec<u8>)> = None;
    let mut expires_hours: u64 = 24;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("multipart error: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                let filename = field.file_name().unwrap_or("upload").to_owned();
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("read error: {e}")))?;
                file_data = Some((filename, data.to_vec()));
            }
            "expires_hours" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("read error: {e}")))?;
                expires_hours = match text.trim() {
                    "1" => 1,
                    "168" => 168,
                    _ => 24,
                };
            }
            _ => {}
        }
    }

    let (filename, data) = file_data
        .ok_or_else(|| json_err(StatusCode::BAD_REQUEST, "missing file field"))?;

    let data_len = u64::try_from(data.len())
        .map_err(|_| json_err(StatusCode::BAD_REQUEST, "file too large"))?;

    if data_len > state.max_file_size {
        return Err(json_err(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds maximum size"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let path = state.storage_dir.join(&id);

    tokio::fs::write(&path, &data)
        .await
        .map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("write error: {e}")))?;

    let now = SystemTime::now();
    let entry = crate::state::TransferEntry {
        id: id.clone(),
        filename,
        size: data_len,
        expires_at: now
            .checked_add(AppState::expiration_duration(expires_hours))
            .unwrap_or(now),
        created_at: now,
    };

    state.transfers.write().await.insert(id.clone(), entry);

    Ok(Json(UploadResponse {
        id,
        expires_in_hours: expires_hours,
    }))
}

/// GET /api/download/{id}
pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let transfers = state.transfers.read().await;
    let entry = transfers.get(&id).ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now();
    if now >= entry.expires_at {
        drop(transfers);
        state.transfers.write().await.remove(&id);
        return Err(StatusCode::GONE);
    }

    let path = state.storage_dir.join(&entry.id);
    drop(transfers);

    let data = tokio::fs::read(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(data)
}

/// GET /api/info/{id}
pub async fn info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let transfers = state.transfers.read().await;
    let entry = transfers.get(&id).ok_or(StatusCode::NOT_FOUND)?;

    let now = SystemTime::now();
    if now >= entry.expires_at {
        drop(transfers);
        state.transfers.write().await.remove(&id);
        return Err(StatusCode::GONE);
    }

    let expires_in_seconds = entry
        .expires_at
        .duration_since(now)
        .map_or(0, |d| d.as_secs());

    let response = InfoResponse {
        id: entry.id.clone(),
        size: entry.size,
        expires_in_seconds,
    };

    drop(transfers);

    Ok(Json(response))
}
