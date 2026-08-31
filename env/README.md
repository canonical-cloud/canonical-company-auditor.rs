# Environment and secrets

The application has no built-in credential and never accepts a secret as a command-line option.
The only current service secret is `CANONICAL_WEBHOOK_SECRET`; runtime probes use an authorized
module name and a numeric bound, not a credential.

Production secret lifecycle must use `ores-sops` with SOPS, age, Just, and Nix under the fleet
contract:

```text
env/enc/<environment>.env.enc   encrypted source of truth; tracked
env/dec/<environment>.env       decrypted runtime material; ignored, mode 0600
```

No ciphertext is committed in the initial repository because no production recipient set or
environment has been authorized for this service yet. When deployment is approved, initialize the
shared `ores-sops` module and recipient policy rather than inventing a repository-specific wrapper.
Never create a plaintext file under `env/enc`, track anything under `env/dec`, put a secret in
`.env.example`, or decrypt during a container build.

For Kubernetes, deliver the small centrally managed runtime secret from the fiducia-cloud
keystore (with the encrypted environment as version-controlled source of truth) and mount/inject it
at runtime. Do not place the value in a manifest, Helm values file, command-line argument, image
layer, GitHub issue, CI output, or model prompt.

Local loopback development does not need a webhook secret. Any non-loopback bind fails unless
`CANONICAL_WEBHOOK_SECRET` is at least 32 bytes; production requires additional authentication,
replay protection, TLS, quotas, and durable audit logging described in `THREAT_MODEL.md`.
