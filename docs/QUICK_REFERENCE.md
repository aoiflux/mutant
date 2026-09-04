# Mutant Security Quick Reference

## What is protected

Mutant now ships with layered anti-tamper and hardening controls for the signed
artifact, runtime, and risky builtins.

## Core controls

1. Signed artifact verification

- Signer pinning is enforced in secure mode when `--signer-auth` is enabled.
- Trusted signer key comes from `--trusted-key <path>`, a file holding the
  hex-encoded public key. Without the flag, Mutant bootstraps and trusts a local
  keypair under `<home>/.mutant/keys`.
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

5. Builtin capability configuration

- Under design. No interface is specified.

6. Release attestation

- Standalone release artifacts use a V3 trailer.
- Trailer fields include payload checksum, canary, build profile code, and
  provenance hash.

7. Remote process scan policy gate

- Off in every shipped binary; reachable only from tests. The manager supports
  `off|observe|enforce` mode, and enforce mode blocks only on critical
  verdicts, but nothing turns it on.

## Protection profile

**Fixed at `standard`.** `ResolveProtectionProfile()` returns it
unconditionally, so posture is not selectable:

- Secure mode is fail-closed; `--compat` and `--dev` are warn-by-default.

`minimal` and `paranoid` still exist as trailer codes so
`ProtectionProfileFromCode` can read back a V3 release trailer written by an
older build. They are unreachable at runtime.

## Configuration

Mutant takes no configuration from environment variables. Everything that shapes
a run is a flag, so the command line is a complete record of it. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

| Flag | Effect |
| --- | --- |
| `--secure` | Secure mode. The default. |
| `--compat` | Weaker checks; tamper response becomes `warn`. |
| `--dev` | Implies `--compat`, plus local password fallback. |
| `--signer-auth` / `--no-signer-auth` | Require or skip trusted signer verification in secure mode. |
| `--trusted-key <path>` | Verify against the hex-encoded public key in this file. |
| `--password <pw>` | Decryption password. |
| `--security-log-level <level>` | Security logging verbosity in dev mode. |
| `--timing` | Per-stage run timing on stderr. |

Run `mutant --help` for the current list.

## Artifact format

Signed `.mu` envelope:

`MUT |-| ENCODED_DATA |-| SIGNATURE_HEX |-| PUBLIC_KEY_HEX |-| ANT`

Standalone release trailer V3:

`MUTANTBC | version | payload_len | payload_sha256 | canary | profile_code | provenance_sha256`

## Operational defaults

- Secure mode: terminate on tamper. Not overridable except by choosing a
  different mode on the command line.
- Compatibility mode: warn on tamper.
- Dev mode: compatibility posture with local password fallback.
- New release builds emit V3 trailers.

## Quick checks

- Unexpected builtin behaviour? There is no capability gate to check: builtin
  capability configuration is under design.
- Signature failure? Check the `--trusted-key` file and the release signer
  chain; without the flag, verification is against the local bootstrap keypair,
  which trusts whatever signed the artifact on this machine.
- Integrity failure? Treat as active tamper.
- Release artifact mismatch? Check trailer profile code and provenance hash.

## Relevant docs

- [docs/SECURITY_LLD.md](docs/SECURITY_LLD.md)
- [docs/SECURITY_RUNBOOK.md](docs/SECURITY_RUNBOOK.md)
- [docs/SECURITY_LLD_TRACEABILITY.md](docs/SECURITY_LLD_TRACEABILITY.md)
