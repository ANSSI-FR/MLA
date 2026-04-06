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
            max_file_size: 2_147_483_648, // 2 GB
        }
    }
}
