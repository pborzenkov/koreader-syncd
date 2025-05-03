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
            .with_max_level(self.verbose.tracing_level_filter())
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
