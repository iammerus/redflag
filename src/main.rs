mod config;
mod error;
mod git_scanner;
mod output;
mod scanner;
mod suppression;

use crate::{config::Config, error::RedflagError, output::OutputHandler, scanner::Scanner};
use clap::{Parser, Subcommand};
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan directory for secrets
    Scan {
        #[arg(default_value = ".")]
        path: String,

        #[arg(short, long)]
        config: Option<PathBuf>,

        #[arg(short, long, value_enum, default_value = "text")]
        format: output::OutputFormat,

        /// Include matched secret values in output
        #[arg(long)]
        show_secrets: bool,

        /// Disable interactive progress output
        #[arg(long)]
        no_progress: bool,

        #[arg(long)]
        git_history: bool,

        #[arg(long, requires = "git_history")]
        git_max_depth: Option<usize>,

        #[arg(long, requires = "git_history")]
        git_since: Option<String>,

        #[arg(long, requires = "git_history")]
        git_until: Option<String>,

        #[arg(long, value_delimiter = ',', requires = "git_history")]
        git_branches: Option<Vec<String>>,
    },
    /// Generate default configuration file
    GenerateConfig {
        #[arg(default_value = "redflag.toml")]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<u8, RedflagError> {
    match cli.command {
        Commands::Scan {
            path,
            config,
            format,
            show_secrets,
            no_progress,
            git_history,
            git_max_depth,
            git_since,
            git_until,
            git_branches,
        } => run_scan(
            path,
            config,
            format,
            show_secrets,
            no_progress,
            git_history,
            GitScanOptions {
                max_depth: git_max_depth,
                branches: git_branches,
                since_date: git_since,
                until_date: git_until,
            },
        ),
        Commands::GenerateConfig { path } => {
            generate_default_config(&path)?;
            Ok(0)
        }
    }
}

fn run_scan(
    path: String,
    config_path: Option<PathBuf>,
    format: output::OutputFormat,
    show_secrets: bool,
    no_progress: bool,
    git_history: bool,
    git_options: GitScanOptions,
) -> Result<u8, RedflagError> {
    let mut config = Config::load(config_path)?;

    // Override git config with CLI options if provided
    if git_history {
        if let Some(depth) = git_options.max_depth {
            config.git.max_depth = depth;
        }
        if let Some(branches) = git_options.branches {
            config.git.branches = branches;
        }
        if let Some(since) = git_options.since_date {
            config.git.since_date = Some(since);
        }
        if let Some(until) = git_options.until_date {
            config.git.until_date = Some(until);
        }
    }
    config.validate()?;
    let history = git_history
        .then(|| git_scanner::HistoryScan::prepare(Path::new(&path), &config.git))
        .transpose()?;

    let scanner = Scanner::with_config(config.clone())?.show_secrets(show_secrets);
    let mut handler = OutputHandler::new(format, !no_progress);

    let working_result = scanner.scan_with_handler(&path, &mut handler);
    if working_result.is_err() {
        handler.clear_progress();
    }
    let working_stats = working_result?;

    let history_stats = if let Some(history) = history {
        let history_result = history.scan(&scanner, &mut handler);
        if history_result.is_err() {
            handler.clear_progress();
        }
        Some(history_result?)
    } else {
        None
    };

    handler.finish(&working_stats, history_stats.as_ref())?;
    Ok(u8::from(handler.findings_count() > 0))
}

struct GitScanOptions {
    max_depth: Option<usize>,
    branches: Option<Vec<String>>,
    since_date: Option<String>,
    until_date: Option<String>,
}

fn generate_default_config(path: &PathBuf) -> Result<(), RedflagError> {
    Config::generate_default_config(path)
}
