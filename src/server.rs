//! Bounded HTTP service for signed assessment requests and inbound evidence webhooks.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

use crate::AuditError;
use crate::engine::assess;
use crate::model::AssessmentRequest;
use crate::program::{AssessmentProgram, built_in_program};
use crate::report::PromptKind;

const SIGNATURE_HEADER: &str = "x-canonical-signature";
const MIN_BODY_BYTES: usize = 1_024;
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// Runtime HTTP service configuration.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Listen socket.
    pub bind: String,
    /// Per-request JSON body limit.
    pub max_body_bytes: usize,
}

#[derive(Clone)]
struct AppState {
    program: Arc<AssessmentProgram>,
    webhook_secret: Option<Arc<[u8]>>,
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
    message: String,
}

/// Starts the HTTP service and shuts down cleanly on Ctrl-C.
///
/// # Errors
///
/// Returns an [`AuditError`] when configuration violates service policy, the built-in program is
/// invalid, the listener cannot bind, or the server exits with an I/O failure.
pub async fn run(config: ServeConfig) -> Result<(), AuditError> {
    if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&config.max_body_bytes) {
        return Err(AuditError::ServerPolicy(format!(
            "max body bytes must be between {MIN_BODY_BYTES} and {MAX_BODY_BYTES}"
        )));
    }
    let address = SocketAddr::from_str(&config.bind)
        .map_err(|_| AuditError::ServerPolicy("bind must be a valid socket address".to_owned()))?;
    let webhook_secret = read_webhook_secret()?;
    if !address.ip().is_loopback() && webhook_secret.is_none() {
        return Err(AuditError::ServerPolicy(
            "non-loopback binding requires CANONICAL_WEBHOOK_SECRET with at least 32 bytes"
                .to_owned(),
        ));
    }

    let state = AppState {
        program: Arc::new(built_in_program()?),
        webhook_secret: webhook_secret.map(Arc::from),
    };
    let app = router(state, config.max_body_bytes);
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(bind = %address, signed = webhook_secret_is_set(), "assessment service listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/catalog", get(catalog))
        .route("/v1/prompts/{name}", get(prompt_template))
        .route("/v1/assessments", post(assessment))
        .route("/v1/webhooks/evidence", post(assessment))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    JsonResponse::ok(json!({
        "status": "ok",
        "service": "canonical-company-auditor",
        "schemaVersion": "canonical.health/v1"
    }))
}

async fn catalog(State(state): State<AppState>) -> impl IntoResponse {
    JsonResponse::ok(state.program.as_ref().clone())
}

async fn prompt_template(Path(name): Path<String>) -> Response {
    match PromptKind::from_str(&name) {
        Ok(kind) => (
            StatusCode::OK,
            [("content-type", "text/markdown; charset=utf-8")],
            kind.template(),
        )
            .into_response(),
        Err(_) => error_response(
            StatusCode::NOT_FOUND,
            "unknown_prompt",
            "unknown prompt name",
        ),
    }
}

async fn assessment(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err((code, message)) = authenticate(&state, &headers, &body) {
        return error_response(StatusCode::UNAUTHORIZED, code, message);
    }
    let Ok(request) = serde_json::from_slice::<AssessmentRequest>(&body) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "body must match canonical.assessment-request/v1 inputs",
        );
    };
    match assess(&request, &state.program) {
        Ok(report) => JsonResponse::ok(report).into_response(),
        Err(error) => error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "assessment_rejected",
            &error.to_string(),
        ),
    }
}

fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), (&'static str, &'static str)> {
    let Some(secret) = &state.webhook_secret else {
        return Ok(());
    };
    let Some(signature) = headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return Err(("signature_required", "signed request required"));
    };
    if verify_signature(secret, body, signature) {
        Ok(())
    } else {
        Err(("invalid_signature", "request signature did not verify"))
    }
}

fn verify_signature(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let Some(encoded) = signature.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(encoded) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

fn read_webhook_secret() -> Result<Option<Vec<u8>>, AuditError> {
    match std::env::var("CANONICAL_WEBHOOK_SECRET") {
        Ok(secret) if secret.len() >= 32 => Ok(Some(secret.into_bytes())),
        Ok(_) => Err(AuditError::ServerPolicy(
            "CANONICAL_WEBHOOK_SECRET must contain at least 32 bytes".to_owned(),
        )),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(AuditError::ServerPolicy(
            "CANONICAL_WEBHOOK_SECRET must be valid UTF-8".to_owned(),
        )),
    }
}

fn webhook_secret_is_set() -> bool {
    std::env::var_os("CANONICAL_WEBHOOK_SECRET").is_some()
}

fn error_response(status: StatusCode, error: &'static str, message: &str) -> Response {
    (
        status,
        axum::Json(ApiError {
            error,
            message: message.to_owned(),
        }),
    )
        .into_response()
}

struct JsonResponse;

impl JsonResponse {
    fn ok<T: Serialize>(value: T) -> impl IntoResponse {
        (StatusCode::OK, axum::Json(value))
    }
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "could not install Ctrl-C handler");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verification_is_exact() -> Result<(), Box<dyn std::error::Error>> {
        let secret = b"01234567890123456789012345678901";
        let body = br#"{"safe":true}"#;
        let mut mac = HmacSha256::new_from_slice(secret)?;
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_signature(secret, body, &signature));
        assert!(!verify_signature(secret, br#"{"safe":false}"#, &signature));
        Ok(())
    }

    #[test]
    fn malformed_signature_fails_closed() {
        assert!(!verify_signature(b"secret", b"body", "sha256=not-hex"));
        assert!(!verify_signature(b"secret", b"body", "not-versioned"));
    }
}
