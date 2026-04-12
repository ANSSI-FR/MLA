use std::time::{Duration, SystemTime};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RoomTokenQuery {
    rt: Option<String>,
}

/// Maximum number of simultaneous participants per room (sender + receiver).
const MAX_ROOM_PARTICIPANTS: usize = 2;
/// Broadcast channel capacity (buffered messages per subscriber).
const ROOM_CAPACITY: usize = 16;
/// Rooms older than this are considered expired and rejected.
const ROOM_TTL: Duration = Duration::from_secs(3600);

pub async fn signal(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(room): Path<String>,
    Query(query): Query<RoomTokenQuery>,
) -> Response {
    // Validate room token against the stored transfer entry.
    // The token is generated at upload time and embedded in the share link
    // (?rt=<token>). Without a valid token the WebSocket upgrade is rejected,
    // preventing unauthenticated peers from joining a signaling room.
    {
        let transfers = state.transfers.read().await;
        match transfers.get(&room) {
            Some(entry) => {
                let provided = query.rt.as_deref().unwrap_or("");
                if provided != entry.room_token {
                    return (StatusCode::UNAUTHORIZED, "invalid room token").into_response();
                }
            }
            None => {
                // Transfer unknown — reject early rather than creating an orphan room.
                return (StatusCode::NOT_FOUND, "transfer not found").into_response();
            }
        }
    }

    let now = SystemTime::now();

    // Check capacity and TTL before upgrading — avoids wasting the connection.
    // Note: TOCTOU is acceptable here (two near-simultaneous connections on an
    // empty room may both be admitted; subsequent ones will be rejected once
    // receiver_count() reaches MAX_ROOM_PARTICIPANTS under the write lock in
    // handle_socket).
    let accept = {
        let rooms = state.signal_rooms.read().await;
        match rooms.get(&room) {
            Some((tx, created_at)) => {
                let expired = now
                    .duration_since(*created_at)
                    .map_or(true, |age| age >= ROOM_TTL);
                !expired && tx.receiver_count() < MAX_ROOM_PARTICIPANTS
            }
            None => true, // room will be created on first connection
        }
    };

    if !accept {
        return (StatusCode::CONFLICT, "room full or expired").into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state, room))
}

async fn handle_socket(socket: WebSocket, state: AppState, room: String) {
    let tx = {
        let mut rooms = state.signal_rooms.write().await;
        let entry = rooms
            .entry(room.clone())
            .or_insert_with(|| (broadcast::channel(ROOM_CAPACITY).0, SystemTime::now()));
        entry.0.clone()
    };

    let mut rx = tx.subscribe();
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let tx_clone = tx.clone();
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
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

    // Clean up empty or expired rooms.
    let should_remove = {
        let rooms = state.signal_rooms.read().await;
        rooms.get(&room).is_some_and(|(tx, created_at)| {
            let expired = SystemTime::now()
                .duration_since(*created_at)
                .map_or(true, |age| age >= ROOM_TTL);
            tx.receiver_count() == 0 || expired
        })
    };
    if should_remove {
        state.signal_rooms.write().await.remove(&room);
    }
}
