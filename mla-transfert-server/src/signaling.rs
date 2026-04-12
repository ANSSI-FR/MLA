use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, State, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
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

    // Clean up empty rooms
    let should_remove = {
        let rooms = state.signal_rooms.read().await;
        rooms
            .get(&room)
            .is_some_and(|sender| sender.receiver_count() == 0)
    };
    if should_remove {
        state.signal_rooms.write().await.remove(&room);
    }
}
