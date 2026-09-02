//! Cross-platform flags-2-env enforcement at the actual argv boundary.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use flags2env::BundledFlags2Env;
use tempfile::TempDir;

const CONTRACT: &str = include_str!("../.cli-flags.toml");

struct MaterializedContract {
    _directory: TempDir,
    path: PathBuf,
}

/// Audits the embedded contract and rejects unknown, invalid, or extra argv values.
///
/// # Errors
///
/// Returns a redacted diagnostic when the contract cannot be materialized/audited or argv does
/// not satisfy it.
pub fn validate_argv(argv: &[String]) -> Result<(), String> {
    let contract = materialize_contract()?;
    validate_with_contract(argv, &contract.path)
}

fn validate_with_contract(argv: &[String], contract_path: &Path) -> Result<(), String> {
    let path = contract_path
        .to_str()
        .ok_or_else(|| "temporary flags contract path is not UTF-8".to_owned())?;
    let parser = BundledFlags2Env::new();
    parser
        .audit_config(Some(path))
        .map_err(|error| format!("flags-2-env configuration audit failed: {error}"))?;
    let parsed = parser
        .parse_structured(argv, Some(path))
        .map_err(|error| format!("flags-2-env could not parse command-line arguments: {error}"))?;

    if !parsed.unknown_options.is_empty() {
        let names = parsed
            .unknown_options
            .iter()
            .map(|option| diagnostic_option_name(option))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!("unknown command-line option(s): {names}"));
    }
    if !parsed.errors.is_empty() {
        return Err(format!(
            "invalid command-line value(s): {} issue(s); run with --help",
            parsed.errors.len()
        ));
    }
    if !parsed.extras.is_empty() {
        return Err(format!(
            "unknown command or unexpected positional argument(s): {} token(s)",
            parsed.extras.len()
        ));
    }
    Ok(())
}

fn materialize_contract() -> Result<MaterializedContract, String> {
    let directory = tempfile::Builder::new()
        .prefix("canonical-auditor-flags-")
        .tempdir()
        .map_err(|error| format!("cannot create flags contract directory: {error}"))?;
    let path = directory.path().join(".cli-flags.toml");
    std::fs::write(&path, CONTRACT)
        .map_err(|error| format!("cannot materialize flags contract: {error}"))?;
    Ok(MaterializedContract {
        _directory: directory,
        path,
    })
}

fn diagnostic_option_name(option: &str) -> String {
    if let Some(long) = option.strip_prefix("--") {
        return format!("--{}", long.split('=').next().unwrap_or_default());
    }
    if option.starts_with('-') {
        return option.chars().take(2).collect();
    }
    "<option>".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_nested_command_is_accepted() -> Result<(), String> {
        validate_argv(&[
            "canonical-auditor".to_owned(),
            "assess".to_owned(),
            "--manifest=examples/company.json".to_owned(),
            "--evidence=examples/evidence.json".to_owned(),
            "--format=markdown".to_owned(),
            "--fail-on=high".to_owned(),
        ])
    }

    #[test]
    fn unknown_option_value_is_not_reflected() {
        let secret = "must-not-appear";
        let result = validate_argv(&[
            "canonical-auditor".to_owned(),
            "catalog".to_owned(),
            format!("--api-key={secret}"),
        ]);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("--api-key"));
        assert!(!error.contains(secret));
    }

    #[test]
    fn credentials_are_absent_from_contract() {
        for forbidden in ["api-key", "bearer-token", "password", "private-key"] {
            assert!(!CONTRACT.contains(forbidden));
        }
    }
}
