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
