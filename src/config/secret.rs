//! Secret resolution. Secrets are never stored in the committed TOML — a field either
//! interpolates `${ENV_VAR}` from the environment or points at a file (Docker secrets).

use anyhow::{anyhow, Context, Result};
use secrecy::SecretString;
use serde::Deserialize;
use std::path::PathBuf;

/// Accepts three TOML spellings:
/// ```toml
/// token = "literal-or-${ENV_VAR}"
/// token = { env = "ENV_VAR" }
/// token = { file = "/run/secrets/token" }
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Secret {
    /// Literal text, with `${VAR}` segments interpolated from the environment at load time.
    Interpolated(String),
    Env { env: String },
    File { file: PathBuf },
}

impl Secret {
    pub fn resolve(&self) -> Result<SecretString> {
        let raw = match self {
            Secret::Interpolated(s) => interpolate(s)?,
            Secret::Env { env } => std::env::var(env)
                .with_context(|| format!("environment variable `{env}` is not set"))?,
            Secret::File { file } => std::fs::read_to_string(file)
                .with_context(|| format!("reading secret file {}", file.display()))?
                // Files written by `echo` or a k8s secret commonly carry a trailing newline.
                .trim_end_matches(['\n', '\r'])
                .to_string(),
        };
        if raw.is_empty() {
            return Err(anyhow!("resolved to an empty secret"));
        }
        Ok(SecretString::from(raw))
    }
}

/// Replaces every `${NAME}` with the environment variable of that name.
fn interpolate(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail
            .find('}')
            .ok_or_else(|| anyhow!("unterminated `${{` in secret value"))?;
        let name = &tail[..end];
        let value = std::env::var(name)
            .with_context(|| format!("environment variable `{name}` is not set"))?;
        out.push_str(&value);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Picks whichever of `field` / `field_file` was supplied. Having both is a config error
/// rather than a silent precedence rule.
pub fn pick(
    label: &str,
    inline: Option<&Secret>,
    file: Option<&PathBuf>,
) -> Result<Option<SecretString>> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(anyhow!(
            "`{label}` and `{label}_file` are both set; use exactly one"
        )),
        (Some(s), None) => Ok(Some(s.resolve().with_context(|| format!("`{label}`"))?)),
        (None, Some(p)) => Ok(Some(
            Secret::File { file: p.clone() }
                .resolve()
                .with_context(|| format!("`{label}_file`"))?,
        )),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn interpolates_env_segments() {
        std::env::set_var("VEDETTE_TEST_TOK", "s3cr3t");
        let s = Secret::Interpolated("Bearer ${VEDETTE_TEST_TOK}!".into());
        assert_eq!(s.resolve().unwrap().expose_secret(), "Bearer s3cr3t!");
    }

    #[test]
    fn missing_env_is_an_error_not_an_empty_string() {
        let s = Secret::Interpolated("${VEDETTE_DEFINITELY_UNSET}".into());
        assert!(s.resolve().is_err());
    }

    #[test]
    fn unterminated_brace_is_rejected() {
        assert!(Secret::Interpolated("${OOPS".into()).resolve().is_err());
    }

    #[test]
    fn file_secret_loses_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tok");
        std::fs::write(&p, "abc123\n").unwrap();
        let s = Secret::File { file: p };
        assert_eq!(s.resolve().unwrap().expose_secret(), "abc123");
    }

    #[test]
    fn both_spellings_at_once_is_rejected() {
        let inline = Secret::Interpolated("x".into());
        let file = PathBuf::from("/tmp/x");
        assert!(pick("password", Some(&inline), Some(&file)).is_err());
    }
}
