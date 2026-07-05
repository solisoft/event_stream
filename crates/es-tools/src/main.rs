mod dump;
mod restore;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "es-tools",
    about = "Offline backup/restore tools for es event log"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create a backup archive from a data directory.
    Dump {
        /// Path to the broker's data directory.
        #[arg(long, default_value = "./data")]
        data_dir: String,

        /// Output path for the backup archive (.tar.gz).
        #[arg(long, default_value = "backup.tar.gz")]
        output: String,

        /// Only include these topics (comma-separated). If omitted, all topics are backed up.
        #[arg(long)]
        topics: Option<String>,

        /// Include API keys (auth secrets) in the backup. By default, keys.json is excluded.
        #[arg(long)]
        include_keys: bool,

        /// Verify segment CRC integrity while copying (slower but validates the backup).
        #[arg(long)]
        verify: bool,
    },

    /// Restore a data directory from a backup archive.
    Restore {
        /// Path to the target data directory (will be created if missing).
        #[arg(long, default_value = "./data")]
        data_dir: String,

        /// Path to the backup archive (.tar.gz).
        #[arg(long, default_value = "backup.tar.gz")]
        input: String,

        /// Overwrite existing data directory contents without confirmation.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Dump {
            data_dir,
            output,
            topics,
            include_keys,
            verify,
        } => {
            let split_topics: Option<Vec<String>> =
                topics.map(|t| t.split(',').map(|s| s.trim().to_string()).collect());
            let topic_filter: Option<Vec<&str>> = split_topics
                .as_ref()
                .map(|v| v.iter().map(|s| s.as_str()).collect());
            dump::dump(
                &data_dir,
                &output,
                topic_filter.as_deref(),
                include_keys,
                verify,
            )?;
        }
        Cmd::Restore {
            data_dir,
            input,
            force,
        } => {
            restore::restore(&input, &data_dir, force)?;
        }
    }
    Ok(())
}
