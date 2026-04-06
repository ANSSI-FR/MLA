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
        Duration::from_secs(hours.saturating_mul(3600))
    }
}
