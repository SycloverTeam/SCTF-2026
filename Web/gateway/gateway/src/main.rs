use std::path::PathBuf;

use clap::Parser;
use gateway::config::Config;
use gateway::server;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "High-performance Tokio + Hyper + Tower API gateway")]
struct Args {
    #[arg(short, long, default_value = "gateway.toml", env = "GATEWAY_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), gateway::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = Config::load_from_path(args.config)?;
    server::run(config).await
}
