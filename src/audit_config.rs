//! Runtime admission for the authoritative `.canonical-cfg.toml` audit manifest.
//!
//! The editable shape authorities live in `canonical-cloud/canonical-interfaces` under
//! `contracts/canonical-audit-config/v1`. This module is a consuming Rust projection with
//! additional fail-closed semantic checks; it is not an independent contract authority.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AuditError;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const SCHEMA_VERSION: &str = "canonical.audit-config.v1";
const CUSTOMER_DIR: &str = "customer";
const CANONICAL_CLI_VERSION: &str = "0.1.0";
const VALIDATOR_ID: &str = "oresoftware/typespec-json-schema-validator";
const VALIDATOR_REVISION: &str = "7b1e79a32b89006a6eb6642ccd71ef25ffac0103";
const VALIDATOR_RECEIPT_SCHEMA: &str = "ores.tjsv.config-instance/v1";
const CONFIG_BRIDGE_ID: &str = "oresoftware/ores-cli";
const CONFIG_BRIDGE_REVISION: &str = "f07b3785a6cd1957591104d19099724452058172";

/// Admitted audit configuration consumed from `.canonical-cfg.toml`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAuditConfig {
    /// Portable schema identifier.
    pub schema_version: String,
    /// Exact toolchain provenance expected by the admitted v1 document.
    pub toolchain: ToolchainPolicy,
    /// Stable customer/engagement identifier.
    pub customer_id: String,
    /// Human-readable customer name.
    pub display_name: String,
    /// Deployment/environment label.
    pub environment: AuditEnvironment,
    /// Audit collectors are always read-only.
    pub audit_mode: String,
    /// Requested readiness framework overlays.
    pub frameworks: FrameworkSelection,
    /// Missing-input behavior.
    pub interaction: InteractionPolicy,
    /// Secret and mutation policy.
    pub security: SecurityPolicy,
    /// Private repository layout.
    pub repository: RepositoryLayout,
    /// Customer publication policy.
    pub publishing: PublishingPolicy,
    /// Provider/service inventory.
    pub services: Vec<ServiceConnection>,
    /// Evidence retention/integrity policy.
    pub evidence: EvidencePolicy,
    /// Report generation policy.
    pub reports: ReportPolicy,
    /// Git persistence policy.
    pub git: GitPolicy,
    /// Optional secret-source references.
    #[serde(default)]
    pub secret_sources: Option<SecretSources>,
}

/// Toolchain provenance carried by every v1 Canonical audit config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainPolicy {
    /// Exact Canonical CLI version expected by the file.
    pub canonical_cli: String,
    /// Shared schema evaluator identity.
    pub validator: String,
    /// Immutable TJSV source revision.
    pub validator_revision: String,
    /// Structured validator receipt protocol.
    pub validator_receipt_schema: String,
    /// Shared native TOML/JSON bridge identity.
    pub config_bridge: String,
    /// Immutable `ores-config-shape` source revision.
    pub config_bridge_revision: String,
    /// v1 requires exact Canonical CLI compatibility.
    pub require_exact_cli_version: bool,
    /// Runtime schema observation is warning-only.
    pub runtime_schema_drift: String,
}

/// Supported environment labels.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditEnvironment {
    /// Non-production testing.
    Test,
    /// Staging/preproduction.
    Staging,
    /// Production/customer engagement.
    Production,
}

/// Readiness framework selection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrameworkSelection {
    /// SOC 2 TSC readiness overlay.
    pub soc2: bool,
    /// NIST CSF 2.0 readiness overlay.
    pub nist_csf_2_0: bool,
    /// NIST SP 800-53 Rev. 5 readiness overlay.
    pub nist_sp_800_53_rev5: bool,
    /// ISO/IEC 27001:2022 readiness overlay.
    pub iso_iec_27001_2022: bool,
}

/// Missing-input interaction policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionPolicy {
    /// Default mode if the command line does not override it.
    pub default_mode: InteractionMode,
    /// Whether an interactive caller may request missing values.
    pub prompt_for_missing: bool,
    /// Whether CLI interactive/non-interactive override is allowed.
    pub allow_interactive_override: bool,
    /// Whether unresolved required fields are fatal in non-interactive mode.
    pub fail_on_missing_required: bool,
}

/// Explicit interaction mode.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum InteractionMode {
    /// Caller may collect missing non-persisted values interactively.
    Interactive,
    /// Missing required values are reported deterministically without prompting.
    NonInteractive,
}

/// Audit security policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPolicy {
    /// Must remain false for audit collection.
    pub allow_mutations: bool,
    /// Must remain false; the manifest stores references only.
    pub allow_plaintext_secrets: bool,
    /// Permitted secret-reference schemes.
    pub secret_reference_schemes: Vec<SecretReferenceScheme>,
    /// Redact logs before persistence/output.
    pub redact_logs: bool,
    /// Redact generated reports.
    pub redact_reports: bool,
    /// Whether secret fingerprints may be recorded.
    pub record_secret_fingerprints: bool,
}

/// Approved secret-reference schemes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
pub enum SecretReferenceScheme {
    /// Environment-variable reference.
    Env,
    /// SOPS/age encrypted-file reference.
    Sops,
    /// Local file reference.
    File,
    /// External vault reference.
    Vault,
}

impl SecretReferenceScheme {
    fn prefix(self) -> &'static str {
        match self {
            Self::Env => "env:",
            Self::Sops => "sops:",
            Self::File => "file:",
            Self::Vault => "vault:",
        }
    }
}

/// Required repository layout.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryLayout {
    /// Customer audit repositories must remain private.
    pub private: bool,
    /// Private normalized evidence directory.
    pub evidence_dir: String,
    /// Private auditor workpapers directory.
    pub workpapers_dir: String,
    /// Private generated reports directory.
    pub reports_dir: String,
    /// Provenance/integrity manifest directory.
    pub manifests_dir: String,
    /// Only publishable repository subtree.
    pub customer_dir: String,
}

/// Customer publication policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishingPolicy {
    /// Whether publication is configured for this engagement.
    pub enabled: bool,
    /// Publication backend.
    pub provider: PublishingProvider,
    /// Allowlisted source directory.
    pub source_dir: String,
    /// Customer visibility policy.
    pub visibility: PublicationVisibility,
    /// Optional customer domain.
    pub custom_domain: Option<String>,
    /// Optional R2 bucket.
    pub r2_bucket: Option<String>,
    /// Optional R2 object prefix.
    pub r2_prefix: Option<String>,
    /// Optional Access policy identifier/name.
    pub access_policy: Option<String>,
    /// Optional cache-control value.
    pub cache_control: Option<String>,
    /// Include the source Git commit in publication provenance.
    pub include_git_commit_sha: bool,
    /// Publish a SHA-256 integrity manifest.
    pub publish_integrity_manifest: bool,
}

/// Supported publication backends.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PublishingProvider {
    /// No publication backend.
    Disabled,
    /// Cloudflare R2 behind the Canonical publication boundary.
    CloudflareR2,
}

/// Customer artifact visibility.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationVisibility {
    /// No unauthenticated access.
    Private,
    /// Access-protected customer delivery.
    Authenticated,
    /// Explicitly public artifacts.
    Public,
}

/// One provider/service connection definition.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConnection {
    /// Stable unique service id.
    pub id: String,
    /// Provider identifier from the admitted contract.
    pub provider: ServiceProvider,
    /// Broad service kind.
    pub kind: ServiceKind,
    /// Whether this provider is in the active collection scope.
    pub enabled: bool,
    /// Must remain true for audit collectors.
    pub read_only: bool,
    /// Secret references only; never resolved values.
    pub auth_refs: Vec<String>,
    /// Read-only resource families to collect.
    pub collect: Vec<String>,
    /// Provider-specific non-secret settings.
    pub settings: ServiceSettings,
}

/// Provider identifier.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceProvider {
    /// GitHub.
    Github,
    /// Amazon Web Services.
    Aws,
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
    /// Cloudflare.
    Cloudflare,
    /// Supabase.
    Supabase,
    /// Neon.
    Neondb,
    /// Vercel.
    Vercel,
    /// Upstash.
    Upstash,
    /// Kubernetes.
    Kubernetes,
    /// Sentry.
    Sentry,
    /// Datadog.
    Datadog,
    /// Explicit extension provider.
    Other,
}

/// Broad service classification.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceKind {
    /// Organization SaaS/control plane.
    Organization,
    /// General cloud provider.
    Cloud,
    /// Edge/network provider.
    Edge,
    /// Managed database platform.
    DatabasePlatform,
    /// Hosting platform.
    Hosting,
    /// Cache/messaging platform.
    CacheMessaging,
    /// Cluster/orchestrator.
    Orchestrator,
    /// Observability platform.
    Observability,
    /// Explicit extension kind.
    Other,
}

/// Provider-specific, non-secret selectors.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    /// Organization/account slug.
    pub organization: Option<String>,
    /// API base URL.
    pub api_base_url: Option<String>,
    /// Provider account id.
    pub account_id: Option<String>,
    /// Regions in scope.
    pub regions: Option<Vec<String>>,
    /// Local profile name.
    pub profile: Option<String>,
    /// Project ids in scope.
    pub project_ids: Option<Vec<String>>,
    /// Tenant id.
    pub tenant_id: Option<String>,
    /// Subscription ids.
    pub subscription_ids: Option<Vec<String>>,
    /// Supabase project refs.
    pub project_refs: Option<Vec<String>>,
    /// Vercel team id.
    pub team_id: Option<String>,
    /// Kubernetes contexts.
    pub contexts: Option<Vec<String>>,
    /// Datadog site.
    pub site: Option<String>,
    /// Generic provider resource ids.
    pub resource_ids: Option<Vec<String>>,
}

/// Evidence persistence/integrity policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePolicy {
    /// Evidence is content-addressed.
    pub content_addressed: bool,
    /// Hash algorithm; currently SHA-256 only.
    pub hash: String,
    /// Whether raw provider responses may be retained.
    pub retain_raw_provider_payloads: bool,
    /// Write normalized evidence artifacts.
    pub write_normalized_evidence: bool,
    /// Write a collection manifest.
    pub write_collection_manifest: bool,
    /// Record evidence provenance.
    pub write_provenance: bool,
}

/// Report policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPolicy {
    /// Requested output formats.
    pub formats: Vec<AuditReportFormat>,
    /// Include framework mappings while avoiding equivalence claims.
    pub include_framework_crosswalk: bool,
    /// Include missing/unknown evidence.
    pub include_evidence_gaps: bool,
    /// Include remediation guidance.
    pub include_remediation: bool,
    /// Include scope and evidence limitations.
    pub include_limitations: bool,
}

/// Supported report format.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditReportFormat {
    /// JSON.
    Json,
    /// Markdown.
    Markdown,
    /// HTML.
    Html,
}

/// Git persistence policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    /// Generated reports may be committed to the private engagement repo.
    pub commit_generated_reports: bool,
    /// Must remain false.
    pub commit_raw_secrets: bool,
    /// Collection/publishing may require a clean worktree.
    pub require_clean_worktree: bool,
    /// Sign/attest publication manifests where configured.
    pub sign_manifest: bool,
}

/// Optional references to approved secret stores/files.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSources {
    /// SOPS/age encrypted-file reference.
    pub sops_age_file: Option<String>,
    /// Local env-file reference.
    pub local_env_file: Option<String>,
    /// External vault references.
    pub vault_paths: Option<Vec<String>>,
}

/// One deterministic missing-input item.
#[derive(Clone, Debug, Serialize)]
pub struct MissingConfigField {
    /// Stable dotted path.
    pub path: String,
    /// Safe reason without secret values.
    pub reason: String,
}

impl CanonicalAuditConfig {
    /// Loads a bounded TOML document and applies all runtime semantic invariants.
    ///
    /// # Errors
    ///
    /// Fails on I/O, oversized input, TOML shape errors, or a semantic safety violation.
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
            return Err(invalid("configuration exceeds 1 MiB"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| invalid("configuration is not UTF-8"))?;
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Applies security, repository-boundary, toolchain, and provider-inventory invariants.
    ///
    /// # Errors
    ///
    /// Fails closed when an audit configuration could mutate customer state, expose secrets,
    /// use an unrecognized validation toolchain, or publish outside the customer allowlist.
    pub fn validate(&self) -> Result<(), AuditError> {
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema_version must be canonical.audit-config.v1",
        )?;
        require(
            self.toolchain.canonical_cli == CANONICAL_CLI_VERSION,
            "toolchain.canonical_cli must match the admitted Canonical CLI version",
        )?;
        require(
            self.toolchain.validator == VALIDATOR_ID,
            "toolchain.validator must use the admitted TJSV validator",
        )?;
        require(
            self.toolchain.validator_revision == VALIDATOR_REVISION,
            "toolchain.validator_revision must match the admitted TJSV revision",
        )?;
        require(
            self.toolchain.validator_receipt_schema == VALIDATOR_RECEIPT_SCHEMA,
            "toolchain.validator_receipt_schema must use the admitted receipt protocol",
        )?;
        require(
            self.toolchain.config_bridge == CONFIG_BRIDGE_ID,
            "toolchain.config_bridge must use the admitted ores-cli bridge",
        )?;
        require(
            self.toolchain.config_bridge_revision == CONFIG_BRIDGE_REVISION,
            "toolchain.config_bridge_revision must match the admitted ores-cli revision",
        )?;
        require(
            self.toolchain.require_exact_cli_version,
            "toolchain.require_exact_cli_version must be true",
        )?;
        require(
            self.toolchain.runtime_schema_drift == "warn",
            "toolchain.runtime_schema_drift must be warn",
        )?;
        require(
            is_lower_hex_revision(&self.toolchain.validator_revision),
            "toolchain.validator_revision must be a lowercase 40-hex revision",
        )?;
        require(
            is_lower_hex_revision(&self.toolchain.config_bridge_revision),
            "toolchain.config_bridge_revision must be a lowercase 40-hex revision",
        )?;
        require(
            !self.customer_id.trim().is_empty(),
            "customer_id must not be empty",
        )?;
        require(
            !self.display_name.trim().is_empty(),
            "display_name must not be empty",
        )?;
        require(
            self.audit_mode == "read-only",
            "audit_mode must be read-only",
        )?;
        require(
            !self.security.allow_mutations,
            "security.allow_mutations must be false",
        )?;
        require(
            !self.security.allow_plaintext_secrets,
            "security.allow_plaintext_secrets must be false",
        )?;
        require(
            !self.security.secret_reference_schemes.is_empty(),
            "security.secret_reference_schemes must not be empty",
        )?;
        require(self.repository.private, "repository.private must be true")?;
        require(
            self.repository.evidence_dir == "evidence",
            "repository.evidence_dir must be evidence",
        )?;
        require(
            self.repository.workpapers_dir == "workpapers",
            "repository.workpapers_dir must be workpapers",
        )?;
        require(
            self.repository.reports_dir == "reports",
            "repository.reports_dir must be reports",
        )?;
        require(
            self.repository.manifests_dir == "manifests",
            "repository.manifests_dir must be manifests",
        )?;
        require(
            self.repository.customer_dir == CUSTOMER_DIR,
            "repository.customer_dir must be customer",
        )?;
        require(
            self.publishing.source_dir == CUSTOMER_DIR,
            "publishing.source_dir must be customer",
        )?;
        require(
            !self.git.commit_raw_secrets,
            "git.commit_raw_secrets must be false",
        )?;
        require(
            self.evidence.hash == "sha256",
            "evidence.hash must be sha256",
        )?;

        if self.publishing.enabled {
            require(
                self.publishing.provider == PublishingProvider::CloudflareR2,
                "enabled publishing must use cloudflare-r2",
            )?;
            require(
                nonempty(&self.publishing.r2_bucket),
                "publishing.r2_bucket is required when publishing is enabled",
            )?;
            require(
                nonempty(&self.publishing.r2_prefix),
                "publishing.r2_prefix is required when publishing is enabled",
            )?;
            require(
                self.publishing.include_git_commit_sha,
                "publishing.include_git_commit_sha must be true",
            )?;
            require(
                self.publishing.publish_integrity_manifest,
                "publishing.publish_integrity_manifest must be true",
            )?;
        }

        let approved_schemes = self
            .security
            .secret_reference_schemes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut ids = BTreeSet::new();
        for service in &self.services {
            require(
                !service.id.trim().is_empty(),
                "service id must not be empty",
            )?;
            require(
                ids.insert(service.id.as_str()),
                "service ids must be unique",
            )?;
            require(service.read_only, "every service must set read_only=true")?;
            if service.enabled {
                require(
                    !service.auth_refs.is_empty(),
                    "enabled services must declare auth_refs",
                )?;
                require(
                    !service.collect.is_empty(),
                    "enabled services must declare a read-only collection scope",
                )?;
            }
            for reference in &service.auth_refs {
                validate_secret_ref(reference, &approved_schemes)?;
            }
        }

        if let Some(sources) = &self.secret_sources {
            for reference in sources
                .sops_age_file
                .iter()
                .chain(sources.local_env_file.iter())
                .chain(sources.vault_paths.iter().flatten())
            {
                validate_secret_ref(reference, &approved_schemes)?;
            }
        }
        Ok(())
    }

    /// Returns deterministic missing provider selectors for enabled services.
    pub fn missing_required_fields(&self) -> Vec<MissingConfigField> {
        let mut missing = Vec::new();
        for service in self.services.iter().filter(|service| service.enabled) {
            let mut push = |field: &str, absent: bool| {
                if absent {
                    missing.push(MissingConfigField {
                        path: format!("services.{}.settings.{field}", service.id),
                        reason: format!(
                            "required for enabled {:?} audit collection",
                            service.provider
                        )
                        .to_ascii_lowercase(),
                    });
                }
            };
            match service.provider {
                ServiceProvider::Github | ServiceProvider::Sentry => {
                    push("organization", blank(&service.settings.organization))
                }
                ServiceProvider::Aws | ServiceProvider::Cloudflare => {
                    push("account_id", blank(&service.settings.account_id))
                }
                ServiceProvider::Gcp | ServiceProvider::Neondb => {
                    push("project_ids", empty_vec(&service.settings.project_ids))
                }
                ServiceProvider::Azure => {
                    push("tenant_id", blank(&service.settings.tenant_id));
                    push(
                        "subscription_ids",
                        empty_vec(&service.settings.subscription_ids),
                    );
                }
                ServiceProvider::Supabase => {
                    push("project_refs", empty_vec(&service.settings.project_refs))
                }
                ServiceProvider::Vercel => push("team_id", blank(&service.settings.team_id)),
                ServiceProvider::Kubernetes => {
                    push("contexts", empty_vec(&service.settings.contexts))
                }
                ServiceProvider::Datadog => push("site", blank(&service.settings.site)),
                ServiceProvider::Upstash | ServiceProvider::Other => {}
            }
        }
        missing.sort_by(|left, right| left.path.cmp(&right.path));
        missing
    }

    /// Returns a deterministic digest of a redacted JSON projection.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn redacted_digest(&self) -> Result<String, AuditError> {
        let value = self.redacted_json()?;
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)))
    }

    /// Returns a JSON projection with secret reference targets removed.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn redacted_json(&self) -> Result<serde_json::Value, AuditError> {
        let mut value = serde_json::to_value(self)?;
        if let Some(services) = value
            .get_mut("services")
            .and_then(serde_json::Value::as_array_mut)
        {
            for service in services {
                if let Some(refs) = service
                    .get_mut("auth_refs")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for reference in refs {
                        if let Some(text) = reference.as_str() {
                            let scheme =
                                text.split_once(':').map_or("secret", |(prefix, _)| prefix);
                            *reference = serde_json::Value::String(format!("{scheme}:<redacted>"));
                        }
                    }
                }
            }
        }
        if let Some(sources) = value.get_mut("secret_sources") {
            redact_strings(sources);
        }
        Ok(value)
    }
}

fn redact_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            let scheme = text.split_once(':').map_or("secret", |(prefix, _)| prefix);
            *text = format!("{scheme}:<redacted>");
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_strings),
        serde_json::Value::Object(map) => map.values_mut().for_each(redact_strings),
        _ => {}
    }
}

fn validate_secret_ref(
    reference: &str,
    approved: &BTreeSet<SecretReferenceScheme>,
) -> Result<(), AuditError> {
    let scheme = approved
        .iter()
        .copied()
        .find(|scheme| reference.starts_with(scheme.prefix()))
        .ok_or_else(|| invalid("secret reference uses an unapproved scheme"))?;
    let target = reference.strip_prefix(scheme.prefix()).unwrap_or_default();
    require(
        !target.trim().is_empty(),
        "secret reference target must not be empty",
    )
}

fn is_lower_hex_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require(condition: bool, reason: &'static str) -> Result<(), AuditError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}

fn invalid(reason: impl Into<String>) -> AuditError {
    AuditError::Invalid {
        field: "canonical-cfg",
        reason: reason.into(),
    }
}

fn nonempty(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn blank(value: &Option<String>) -> bool {
    !nonempty(value)
}

fn empty_vec(value: &Option<Vec<String>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema_version = "canonical.audit-config.v1"
customer_id = "demo"
display_name = "Demo"
environment = "test"
audit_mode = "read-only"
[toolchain]
canonical_cli = "0.1.0"
validator = "oresoftware/typespec-json-schema-validator"
validator_revision = "7b1e79a32b89006a6eb6642ccd71ef25ffac0103"
validator_receipt_schema = "ores.tjsv.config-instance/v1"
config_bridge = "oresoftware/ores-cli"
config_bridge_revision = "f07b3785a6cd1957591104d19099724452058172"
require_exact_cli_version = true
runtime_schema_drift = "warn"
[frameworks]
soc2 = true
nist_csf_2_0 = true
nist_sp_800_53_rev5 = true
iso_iec_27001_2022 = true
[interaction]
default_mode = "non-interactive"
prompt_for_missing = false
allow_interactive_override = true
fail_on_missing_required = true
[security]
allow_mutations = false
allow_plaintext_secrets = false
secret_reference_schemes = ["env", "sops", "file", "vault"]
redact_logs = true
redact_reports = true
record_secret_fingerprints = false
[repository]
private = true
evidence_dir = "evidence"
workpapers_dir = "workpapers"
reports_dir = "reports"
manifests_dir = "manifests"
customer_dir = "customer"
[publishing]
enabled = true
provider = "cloudflare-r2"
source_dir = "customer"
visibility = "authenticated"
r2_bucket = "demo"
r2_prefix = "demo/"
include_git_commit_sha = true
publish_integrity_manifest = true
[[services]]
id = "github"
provider = "github"
kind = "organization"
enabled = true
read_only = true
auth_refs = ["env:GITHUB_TOKEN"]
collect = ["repositories"]
[services.settings]
organization = "canonical-cloud"
[evidence]
content_addressed = true
hash = "sha256"
retain_raw_provider_payloads = false
write_normalized_evidence = true
write_collection_manifest = true
write_provenance = true
[reports]
formats = ["json", "markdown", "html"]
include_framework_crosswalk = true
include_evidence_gaps = true
include_remediation = true
include_limitations = true
[git]
commit_generated_reports = true
commit_raw_secrets = false
require_clean_worktree = true
sign_manifest = true
"#;

    fn parse(input: &str) -> Result<CanonicalAuditConfig, AuditError> {
        let config: CanonicalAuditConfig = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn authoritative_shape_is_accepted() {
        let config = parse(VALID).expect("valid config");
        assert!(config.missing_required_fields().is_empty());
    }

    #[test]
    fn mutation_is_rejected() {
        let input = VALID.replace("allow_mutations = false", "allow_mutations = true");
        assert!(parse(&input).is_err());
    }

    #[test]
    fn stale_validator_revision_is_rejected() {
        let input = VALID.replace(
            VALIDATOR_REVISION,
            "0000000000000000000000000000000000000000",
        );
        assert!(parse(&input).is_err());
    }

    #[test]
    fn wrong_config_bridge_is_rejected() {
        let input = VALID.replace(CONFIG_BRIDGE_ID, "example/config-bridge");
        assert!(parse(&input).is_err());
    }

    #[test]
    fn wrong_publication_root_is_rejected() {
        let input = VALID.replace("source_dir = \"customer\"", "source_dir = \"evidence\"");
        assert!(parse(&input).is_err());
    }

    #[test]
    fn plaintext_secret_field_is_rejected_by_shape() {
        let input = VALID.replace(
            "organization = \"canonical-cloud\"",
            "organization = \"canonical-cloud\"\ntoken = \"secret\"",
        );
        assert!(toml::from_str::<CanonicalAuditConfig>(&input).is_err());
    }

    #[test]
    fn duplicate_service_ids_are_rejected() {
        let service = r#"
[[services]]
id = "github"
provider = "other"
kind = "other"
enabled = false
read_only = true
auth_refs = []
collect = []
[services.settings]
"#;
        assert!(parse(&format!("{VALID}{service}")).is_err());
    }

    #[test]
    fn redaction_removes_reference_targets() {
        let config = parse(VALID).expect("valid config");
        let rendered =
            serde_json::to_string(&config.redacted_json().expect("redacted")).expect("json");
        assert!(!rendered.contains("GITHUB_TOKEN"));
        assert!(rendered.contains("env:<redacted>"));
        assert_eq!(config.redacted_digest().expect("digest").len(), 64);
    }
}
