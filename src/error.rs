use indicatif::style::TemplateError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedflagError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("Template error: {0}")]
    Template(String),
}

impl From<toml::de::Error> for RedflagError {
    fn from(e: toml::de::Error) -> Self {
        RedflagError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for RedflagError {
    fn from(e: toml::ser::Error) -> Self {
        RedflagError::Config(e.to_string())
    }
}

impl From<TemplateError> for RedflagError {
    fn from(e: TemplateError) -> Self {
        RedflagError::Template(e.to_string())
    }
}
