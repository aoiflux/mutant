# Binary Artifact Security Deep Dive

## 1. Scope

This deep dive covers binary artifact security for Mutant from generation to
runtime load:

1. Signed `.mu` envelope format and trust model.
2. Standalone trailer V1/V2/V3 validation and provenance checks.
3. Runtime mode and signer-auth behavior at load time.
4. Failure paths and telemetry hooks.

Primary implementation anchors:

1. `security/signatures.go`
2. `security/signing.go`
3. `security/key_bootstrap.go`
4. `generator/writebinary.go`
5. `runner/runner.go`

## 2. Signed Envelope Security

Mutant signed payload format:

`MUT |-| ENCODED_DATA |-| SIGNATURE_HEX |-| PUBLIC_KEY_HEX |-| ANT`

Verification paths:

1. `VerifyCode`

- Validates envelope structure and Ed25519 signature with embedded key.
- Used in compatibility mode.

2. `VerifyCodeWithTrustedPublicKey`

- Validates envelope and signature.
- Requires trusted key pinning material.
- Rejects if embedded key does not match trusted key (`ErrUntrustedSigner`).

## 3. Signer Trust Resolution

Trusted key resolution order when signer-auth path is used:

1. If `MUTANT_TRUSTED_PUBLIC_KEY_HEX` is set, use it.
2. Otherwise bootstrap/load local keypair in keystore and trust local public
   key.

Key files:

1. `ed25519_private_key.hex`
2. `ed25519_public_key.hex`

Default key dir:

`<home>/.mutant/keys`

Override:

`MUTANT_KEYSTORE_DIR`

## 4. Runtime Signature Decision Matrix

The runner behavior is controlled by two switches:

1. `secureMode` (derived from CLI mode flags)
2. `enforceSignerAuth` (derived from `--signer-auth` / `--no-signer-auth`)

Behavior:

1. `secureMode=true`, `enforceSignerAuth=true`

- Runs trusted-key signature verification.
- Signature errors go through tamper policy.

2. `secureMode=true`, `enforceSignerAuth=false`

- Skips signature verification path.
- Continues to anti-debug/sandbox/process protection and decode path.

3. `secureMode=false`

- Runs compatibility signature verification path.
- Signature failures are policy-driven (`warn|delay|terminate`).

## 5. Standalone Trailer Attestation

Release binaries append a trailer after payload:

V3 format:

`MUTANTBC | version | payload_len | payload_sha256 | canary | profile_code | provenance_sha256`

Validation order in runner:

1. Try V3 trailer.
2. Fall back to V2.
3. Fall back to V1.

Validation checks:

1. Marker and version.
2. Payload length bounds.
3. Payload checksum.
4. Canary (V2+).
5. Profile code validity and provenance hash (V3).

Tamper outcomes:

1. Mismatch returns explicit trailer error (checksum/canary/provenance/version).
2. Runner rejects payload extraction on trailer validation failure.

## 6. Profile Binding and Provenance

Generation path binds runtime profile code into trailer:

1. `generator/writebinary.go` calls `ResolveProtectionProfileCode`.
2. Profile code is embedded as one byte.
3. Provenance hash derives from payload + payload hash + profile code.

Security value:

1. Build profile is auditable from artifact.
2. Payload replay or profile mismatch changes provenance digest.

## 7. Policy and Telemetry Coupling

When signature verification runs and fails:

1. `RecordSignatureFailure(stage)` increments telemetry.
2. `ApplyTamperResponse(...)` executes warn/delay/terminate policy.

Telemetry export:

1. Optional on process exit via `MUTANT_SECURITY_TELEMETRY_FILE`.
2. Optional audit stream via `MUTANT_SECURITY_AUDIT=1`.

## 8. Operational Pitfalls

1. Secure mode does not imply signer-auth unless `--signer-auth` is supplied.
2. Compatibility mode can continue past signature failures under warn/delay.
3. Local key bootstrap is convenient but must be governed for production trust.
4. Environment policy overrides can intentionally downgrade response severity.

## 9. Recommended Production Posture

1. Use `--secure --signer-auth`.
2. Set `MUTANT_TRUSTED_PUBLIC_KEY_HEX` to approved release signer.
3. Set `MUTANT_TAMPER_RESPONSE=terminate`.
4. Enable `MUTANT_SECURITY_AUDIT=1` and telemetry export.
