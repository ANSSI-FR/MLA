use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{RwLock, broadcast};

/// A signal room: broadcast channel + creation timestamp for TTL enforcement.
pub type RoomEntry = (broadcast::Sender<String>, SystemTime);

#[derive(Debug, Clone)]
#[allow(dead_code)]
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
    pub signal_rooms: Arc<RwLock<HashMap<String, RoomEntry>>>,
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
        Duration::from_secs(hours.saturating_mul(3600))
    }
}
