# Mutant Security Quick Reference

## What is protected

Mutant now ships with layered anti-tamper and hardening controls for the signed
artifact, runtime, and risky builtins.

## Core controls

1. Signed artifact verification

- Signer pinning is enforced in secure mode when `--signer-auth` is enabled.
- Trusted signer key source is `MUTANT_TRUSTED_PUBLIC_KEY_HEX` (or local
  bootstrap fallback if unset).
- Compatibility mode verifies embedded signature validity only.

2. Payload confidentiality

- Bytecode is protected with AES-GCM plus offset-aware stream masking.
- Password-based builds use Argon2id derivation.

3. Runtime integrity

- VM integrity checks run periodically, with seeded jitter and sweep probes.
- Tamper detection triggers policy-driven response and telemetry.

4. Anti-debugging

- Pre-decode and pre-execution debugger checks run in the launcher path.
- Platform-specific heuristics are used under `security/antidebug_*`.

5. Builtin capability gating

- Risky builtin groups are default-denied unless explicitly allowed.
- Groups: `command_exec`, `filesystem`, `network`.

6. Release attestation

- Standalone release artifacts use a V3 trailer.
- Trailer fields include payload checksum, canary, build profile code, and
  provenance hash.

7. Remote process scan policy gate

- Optional remote scan manager can run in `off|observe|enforce` mode.
- Enforce mode blocks only on critical verdicts.

## Protection profiles

Set `MUTANT_PROTECTION_PROFILE` to control default posture.

- `minimal`
- Defaults tamper response to `warn`.
- Defaults risky builtin groups to allow-all unless explicitly constrained.

- `standard`
- Default when unset or invalid.
- Keeps secure mode fail-closed and compat mode warn-by-default.
- Risky builtins default to deny unless explicitly allowed.

- `paranoid`
- Defaults tamper response to `terminate`.
- Risky builtins default to deny unless explicitly allowed.

Explicit environment variables still win:

- `MUTANT_TAMPER_RESPONSE`
- `MUTANT_BUILTIN_CAPABILITIES`

## Useful environment variables

- `MUTANT_TRUSTED_PUBLIC_KEY_HEX`
- `MUTANT_SIGNING_PRIVATE_KEY_HEX`
- `MUTANT_TAMPER_RESPONSE`
- `MUTANT_TAMPER_DELAY_MS`
- `MUTANT_PROTECTION_PROFILE`
- `MUTANT_BUILTIN_CAPABILITIES`
- `MUTANT_SECURITY_AUDIT`
- `MUTANT_SECURITY_TELEMETRY_FILE`
- `MUTANT_ENABLE_REMOTE_PROCESS_SCAN`
- `MUTANT_REMOTE_SCAN_MODE`
- `MUTANT_REMOTE_SCAN_MAX_PROCESSES`
- `MUTANT_REMOTE_SCAN_ALLOWLIST`

## Artifact format

Signed `.mu` envelope:

`MUT |-| ENCODED_DATA |-| SIGNATURE_HEX |-| PUBLIC_KEY_HEX |-| ANT`

Standalone release trailer V3:

`MUTANTBC | version | payload_len | payload_sha256 | canary | profile_code | provenance_sha256`

## Operational defaults

- Secure mode: terminate on tamper unless explicitly overridden.
- Compatibility mode: warn on tamper unless explicitly overridden.
- Dev mode: compatibility posture with local password fallback.
- New release builds emit V3 trailers.

## Quick checks

- Unexpected builtins blocked? Check `MUTANT_PROTECTION_PROFILE` and
  `MUTANT_BUILTIN_CAPABILITIES`.
- Signature failure? Check trusted key pinning and release signer chain.
- Integrity failure? Treat as active tamper.
- Release artifact mismatch? Check trailer profile code and provenance hash.

## Relevant docs

- [docs/SECURITY_LLD.md](docs/SECURITY_LLD.md)
- [docs/SECURITY_RUNBOOK.md](docs/SECURITY_RUNBOOK.md)
- [docs/SECURITY_LLD_TRACEABILITY.md](docs/SECURITY_LLD_TRACEABILITY.md)
