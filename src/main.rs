mod artifacts;
mod changes;
mod config;
mod engine;
mod error;
mod git_scanner;
mod manifest;
mod output;
mod protected_values;
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
    /// Inspect every introduced commit using policy from the trusted base
    Changes(changes::ChangeArgs),
    /// Inspect every file selected for publication; exit 2 if inspection is incomplete
    Artifacts {
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Use built-in defaults without discovering redflag.toml
        #[arg(long, conflicts_with = "config")]
        no_config: bool,
        #[arg(short, long, value_enum, default_value = "text")]
        format: output::OutputFormat,
        /// Match the exact value of this environment variable (repeat for each name)
        #[arg(long, value_name = "NAME")]
        private_env: Vec<String>,
        /// Explicitly accept a declared private value shorter than 8 bytes
        #[arg(long, value_name = "NAME")]
        allow_short_private_value: Vec<String>,
        /// Write a clean-scan manifest outside the selected publication inputs
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
        /// General credential detector; native retains the legacy rule behavior
        #[arg(long, value_enum, default_value = "betterleaks")]
        engine: engine::EngineChoice,
        /// Path to the checksum-verified pinned Betterleaks executable
        #[arg(long)]
        betterleaks_path: Option<PathBuf>,
    },
    /// Verify that publication inputs still match a clean artifact scan
    VerifyArtifacts {
        manifest: PathBuf,
        /// Replacement publication root (repeat in original target order)
        #[arg(long, value_name = "PATH")]
        target: Vec<PathBuf>,
        #[arg(short, long, value_enum, default_value = "text")]
        format: output::OutputFormat,
    },
    /// Show the resolved, merged and validated policy for a source target
    ShowConfig {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long, conflicts_with = "config")]
        no_config: bool,
        #[arg(short, long, value_enum, default_value = "text")]
        format: output::OutputFormat,
    },
    /// Scan directory for secrets
    Scan {
        #[arg(default_value = ".")]
        path: String,

        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Use built-in defaults without discovering redflag.toml
        #[arg(long, conflicts_with = "config")]
        no_config: bool,

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
        Commands::Changes(args) => changes::run(args),
        Commands::Artifacts {
            paths,
            config,
            no_config,
            format,
            private_env,
            allow_short_private_value,
            manifest,
            engine: engine_choice,
            betterleaks_path,
        } => {
            let manifest_output = manifest
                .as_ref()
                .map(|path| manifest::ManifestOutput::prepare(path, &paths))
                .transpose()?;
            let config_path = Config::resolve_path(config, &std::env::current_dir()?, no_config)?;
            let config = Config::load(config_path)?;
            let config_sha256 = artifacts::digest(&serde_json::to_vec(&config)?);
            let engine = engine::GeneralEngine::prepare(
                engine_choice,
                betterleaks_path,
                config.limits.engine_timeout_seconds,
                config_sha256.clone(),
            )?;
            let mut scanner = Scanner::with_config(config)?;
            if engine_choice == engine::EngineChoice::Betterleaks {
                scanner = scanner.for_external_engine();
            }
            let protected =
                protected_values::ProtectedValues::load(&private_env, &allow_short_private_value)?;
            let selected = artifacts::ArtifactSet::collect(&paths, scanner.limits())?;
            let mut handler = OutputHandler::new(format, false);
            let coverage = selected.scan(&scanner, &protected, engine, &mut handler)?;
            let exit = u8::from(handler.findings_count() > 0);
            if exit == 0 {
                if let Some(manifest) = manifest_output {
                    manifest.write(&coverage, config_sha256)?;
                }
            }
            if let Err(error) = handler.finish_report("artifacts", &coverage) {
                if let Some(path) = manifest {
                    let _ = std::fs::remove_file(path);
                }
                return Err(error);
            }
            Ok(exit)
        }
        Commands::VerifyArtifacts {
            manifest,
            target,
            format,
        } => {
            let verification = manifest::verify(&manifest, &target)?;
            OutputHandler::new(format, false).finish_report("verify_artifacts", &verification)?;
            Ok(0)
        }
        Commands::ShowConfig {
            path,
            config,
            no_config,
            format,
        } => {
            let config_path = Config::resolve_path(config, &path, no_config)?;
            let effective = Config::load(config_path.clone())?;
            let _scanner = Scanner::with_config(effective.clone())?;
            #[derive(serde::Serialize)]
            struct EffectiveConfig {
                schema_version: u32,
                config_path: Option<PathBuf>,
                sha256: String,
                effective: Config,
            }
            let report = EffectiveConfig {
                schema_version: 1,
                config_path,
                sha256: artifacts::digest(&serde_json::to_vec(&effective)?),
                effective,
            };
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            use std::io::Write;
            match format {
                output::OutputFormat::Json => serde_json::to_writer_pretty(&mut writer, &report)?,
                output::OutputFormat::Text => {
                    writeln!(
                        writer,
                        "# Configuration: {}",
                        report
                            .config_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "built-in defaults".into())
                    )?;
                    writeln!(writer, "# SHA-256: {}", report.sha256)?;
                    writer.write_all(toml::to_string_pretty(&report.effective)?.as_bytes())?;
                }
            }
            writeln!(writer)?;
            Ok(0)
        }
        Commands::Scan {
            path,
            config,
            no_config,
            format,
            show_secrets,
            no_progress,
            git_history,
            git_max_depth,
            git_since,
            git_until,
            git_branches,
        } => {
            let config_path = Config::resolve_path(config, Path::new(&path), no_config)?;
            run_scan(
                path,
                config_path,
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
            )
        }
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
    let scanner = Scanner::with_config(config.clone())?.show_secrets(show_secrets);
    let history = git_history
        .then(|| git_scanner::HistoryScan::prepare(Path::new(&path), &config.git))
        .transpose()?;

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
