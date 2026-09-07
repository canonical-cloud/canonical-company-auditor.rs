//! End-to-end flags-2-env and CLI file-boundary regression tests.
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn run(context: &Path, output: &Path, responses: Option<&Path>) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_canonical-auditor"));
    command
        .env_clear()
        .args(["readiness", "--framework", "soc2", "--format", "json"]);
    command
        .arg("--context")
        .arg(context)
        .arg("--output")
        .arg(output);
    if let Some(path) = responses {
        command.arg("--responses").arg(path);
    }
    command.output()
}

#[test]
fn export_assess_and_refuse_overwrite() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let context = directory.path().join("context.json");
    fs::write(
        &context,
        include_bytes!("../readiness/context.example.json"),
    )?;
    let answers = directory.path().join("answers.json");
    assert!(run(&context, &answers, None)?.status.success());
    let original = fs::read(&answers)?;
    let response: Value = serde_json::from_slice(&original)?;
    assert_eq!(response["frameworkId"], "soc2");
    assert!(!run(&context, &answers, None)?.status.success());
    assert_eq!(fs::read(&answers)?, original);
    let report = directory.path().join("report.json");
    assert_eq!(
        run(&context, &report, Some(&answers))?.status.code(),
        Some(2)
    );
    let result: Value = serde_json::from_slice(&fs::read(report)?)?;
    assert_eq!(result["summary"]["answered"], 0);
    assert_eq!(result["summary"]["total"], 10);
    assert_eq!(result["assurance"], "none");
    Ok(())
}

#[test]
fn mismatch_and_bad_customer_data_never_write_a_report() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let context = directory.path().join("context.json");
    fs::write(
        &context,
        include_bytes!("../readiness/context.example.json"),
    )?;
    let answers = directory.path().join("answers.json");
    assert!(run(&context, &answers, None)?.status.success());
    let original: Value = serde_json::from_slice(&fs::read(&answers)?)?;
    for field in ["frameworkId", "catalogVersion", "schemaVersion"] {
        let mut wrong = original.clone();
        wrong[field] = json!("PRIVATE_CANARY");
        fs::write(&answers, serde_json::to_vec(&wrong)?)?;
        let report = directory.path().join(format!("{field}.json"));
        let result = run(&context, &report, Some(&answers))?;
        assert!(!result.status.success());
        assert!(!report.exists());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("PRIVATE_CANARY"));
    }
    Ok(())
}
