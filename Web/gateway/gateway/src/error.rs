use thiserror::Error;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("http construction error: {0}")]
    Http(#[from] http::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml decode error: {0}")]
    Toml(#[from] toml::de::Error),
}
