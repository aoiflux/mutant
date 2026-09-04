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

Trusted key resolution order when signer-auth path is used
(`ResolveTrustedPublicKeyHexFromPath`, security/key_bootstrap.go):

1. If `--trusted-key <path>` was given, read the hex-encoded public key from
   that file. A malformed, wrong-sized or missing file is a hard failure: there
   is no silent fallback to the keystore, because verifying against a key the
   operator did not name is worse than refusing to run.
2. Otherwise bootstrap/load the local keypair in the keystore and trust the
   local public key.

The flag carries a *path*, never key material. Key material in an environment
variable is invisible in the command an analyst records and is inherited by
every child process; a path is safe to write into case notes. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

Key files:

1. `ed25519_private_key.hex`
2. `ed25519_public_key.hex`

Key dir:

`<home>/.mutant/keys`, fixed. `SetLocalKeyStoreDirForTesting` redirects it for
tests only.

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

1. In-process only. `SecurityTelemetrySnapshot()` and
   `SecurityTelemetryJSON()` read the counters;
   `ExportSecurityTelemetry(path)` writes them to a file, but nothing in the
   runner calls it.
2. There is no audit stream: `auditEvent` is a no-op.

## 8. Operational Pitfalls

1. Secure mode does not imply signer-auth unless `--signer-auth` is supplied.
2. Compatibility mode can continue past signature failures under warn.
3. Local key bootstrap is convenient, but a bootstrapped key trusts whatever
   signed the artifact on this machine. Pass `--trusted-key` to pin a real
   signer.
4. `--compat` and `--dev` downgrade the tamper response to a warning. This is
   the only way to soften it, it is visible in the command line, and it cannot
   be done behind an operator's back.

## 9. Recommended Production Posture

1. Use `--secure --signer-auth`.
2. Pass `--trusted-key <path>` naming the approved release signer's public key.
3. Do not pass `--compat` or `--dev`: secure mode already terminates on a tamper
   event, and that is the only way to get `terminate`.
4. Record the full command line alongside the artifact. It is the complete
   description of how the run was configured -- nothing is read from the
   environment. See [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).
