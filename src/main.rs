use std::path::Path;

use anyhow::{Context, Result};
use args::Args;
use clap::Parser;
use sqlx::{
    migrate,
    sqlite::{SqliteConnectOptions, SqliteJournalMode},
    SqlitePool,
};

mod api;
mod args;

#[tokio::main]
async fn main() {
    if let Err(err) = try_main().await {
        eprintln!("ERROR: {:#}", err);
        std::process::exit(1);
    }
}

async fn try_main() -> Result<()> {
    let args = Args::parse();
    args.init_tracing();

    let pool = get_db_pool(&args.db).await?;

    let app = api::get_router(pool);

    axum::Server::bind(&args.address)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn get_db_pool<T: AsRef<Path>>(path: T) -> Result<SqlitePool> {
    let path = path.as_ref();

    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(SqliteJournalMode::Wal)
            .create_if_missing(true),
    )
    .await
    .with_context(|| format!("Could not open DB '{}'", path.display()))?;

    migrate!("./migrations")
        .run(&pool)
        .await
        .context("Could not apply migrations")?;

    Ok(pool)
}
