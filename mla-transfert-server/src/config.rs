use std::path::PathBuf;

pub struct ServerConfig {
    pub port: u16,
    pub storage_dir: PathBuf,
    pub max_file_size: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let port = std::env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3001);

        let storage_dir = std::env::var("STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data/uploads"));

        let max_file_size = std::env::var("MAX_FILE_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_147_483_648); // 2 GB

        Self {
            port,
            storage_dir,
            max_file_size,
        }
    }
}
