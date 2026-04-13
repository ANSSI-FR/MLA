use std::time::SystemTime;

use axum::Json;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::json;

/// Helper : retourne toujours une erreur JSON `{"error": "..."}`.
fn json_err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({ "error": msg.into() })))
}

/// Strip path traversal components and keep only safe characters.
/// Allows alphanumerics, spaces, dots, hyphens and underscores; max 255 bytes.
fn sanitize_filename(raw: &str) -> String {
    // Take the last path component only (strips directory traversal).
    let name = raw.rsplit(['/', '\\']).next().unwrap_or("upload");

    let clean: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
        .collect();

    let trimmed = clean.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "upload".to_string();
    }

    // Limit to 255 UTF-8 bytes (filesystem limit on most systems).
    let mut result = trimmed.to_string();
    while result.len() > 255 {
        result.pop();
    }
    result
}

type JsonError = (StatusCode, Json<serde_json::Value>);

use crate::state::AppState;

#[derive(Serialize)]
pub struct UploadResponse {
    id: String,
    expires_in_hours: u64,
    room_token: String,
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

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("multipart error: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "file" => {
                let filename = sanitize_filename(field.file_name().unwrap_or("upload"));
                // Stream chunk-by-chunk so we can enforce the size limit
                // incrementally rather than buffering the whole body first.
                let mut data: Vec<u8> = Vec::new();
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("read error: {e}")))?
                {
                    data.extend_from_slice(&chunk);
                    if u64::try_from(data.len()).unwrap_or(u64::MAX) > state.max_file_size {
                        return Err(json_err(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "file exceeds maximum size",
                        ));
                    }
                }
                file_data = Some((filename, data));
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

    let (filename, data) =
        file_data.ok_or_else(|| json_err(StatusCode::BAD_REQUEST, "missing file field"))?;

    // Size was already checked incrementally during streaming; this conversion
    // is safe since data.len() <= max_file_size which fits in u64.
    let data_len = data.len() as u64;

    let id = uuid::Uuid::new_v4().to_string();
    let room_token = uuid::Uuid::new_v4().to_string();
    let path = state.storage_dir.join(&id);

    tokio::fs::write(&path, &data).await.map_err(|e| {
        json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write error: {e}"),
        )
    })?;

    let now = SystemTime::now();
    let entry = crate::state::TransferEntry {
        id: id.clone(),
        filename,
        size: data_len,
        expires_at: now
            .checked_add(AppState::expiration_duration(expires_hours))
            .unwrap_or(now),
        created_at: now,
        room_token: room_token.clone(),
    };

    state.transfers.write().await.insert(id.clone(), entry);

    Ok(Json(UploadResponse {
        id,
        expires_in_hours: expires_hours,
        room_token,
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
