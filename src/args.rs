use clap::Parser;
use clap_verbosity_flag::Verbosity;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Address to listen on
    #[clap(short, long, default_value = "127.0.0.1:3131")]
    pub address: SocketAddr,
    /// Database path
    #[clap(short, long)]
    pub db: PathBuf,
    /// enable register
    #[clap(short, long)]
    pub enable_register: bool,

    #[clap(flatten)]
    pub verbose: Verbosity,
}

impl Args {
    pub fn init_tracing(&self) {
        tracing_subscriber::fmt()
            .with_max_level(match self.verbose.log_level_filter() {
                log::LevelFilter::Off => tracing_subscriber::filter::LevelFilter::OFF,
                log::LevelFilter::Error => tracing_subscriber::filter::LevelFilter::ERROR,
                log::LevelFilter::Warn => tracing_subscriber::filter::LevelFilter::WARN,
                log::LevelFilter::Info => tracing_subscriber::filter::LevelFilter::INFO,
                log::LevelFilter::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
                log::LevelFilter::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
            })
            .init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Args::command().debug_assert();
    }
}
