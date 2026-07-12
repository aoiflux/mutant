# Security Answers (Current Code)

This FAQ is the student-friendly, code-accurate version of Mutant security
behavior.

## 1) Is encryption password-based or deterministic?

Both are supported.

1. If password is provided (`-password` or `-pwd`), password-based KDF path is
   used.
2. If password is omitted, deterministic mode is used.

In both modes, runtime decrypts before execution and does not rely on plaintext
bytecode files.

## 2) How is authenticity enforced?

Mutant signs and verifies artifacts using Ed25519-based signing flow.

Secure mode behavior:

1. Secure mode is default.
2. Signer-auth is optional and can be explicitly enforced with `--signer-auth`.
3. Without `--signer-auth`, secure mode keeps runtime hardening gates but does
   not run signer pinning verification.
4. Trusted key pinning uses `MUTANT_TRUSTED_PUBLIC_KEY_HEX`.

Compatibility/dev behavior:

1. More permissive by default.
2. Still supports policy-driven handling through tamper response configuration.

## 3) What are secure/compat/dev modes?

1. Secure mode (`--secure`, default): fail-closed defaults.
2. Compat mode (`--compat`): warn-oriented defaults.
3. Dev mode (`--dev`): compat posture plus local convenience defaults.

CLI rule: last mode flag wins when multiple are passed.

## 4) Is anti-debugging implemented?

Yes.

1. Platform-specific detection exists in `security/antidebug_*.go`.
2. Runner enforces anti-debug checks at:
   - pre-decode
   - pre-execution
3. Action is policy-driven (`warn`, `delay`, `terminate`).

## 5) Is sandbox detection implemented?

Yes.

1. Platform-specific detectors exist for Windows, Linux, and macOS with stubs
   where needed.
2. Runner enforces sandbox checks at pre-decode and pre-execution.
3. Builtin diagnostics can report sandbox type, confidence, and indicators.

## 6) Is process injection detection implemented?

Yes, as anti-tamper process-protection probes.

Important gates:

1. `MUTANT_ENABLE_ANTITAMPER_PROBE=1` must be set to run probes.
2. `MUTANT_ENABLE_PROCESS_PROTECTION` controls runner enforcement once probes
   are enabled.

Runner enforcement probes:

1. process_injection
2. trampoline
3. iat_got
4. module_integrity
5. memory_page_anomaly

Threshold:

1. `detected=true` with `confidence >= 80` is treated as process protection
   event.

## 7) Are polymorphic mutations fully active?

Partially.

Current state:

1. Polymorphic engine is integrated and marker/tagging is active.
2. Mutation level and seed flags are wired through CLI paths.
3. Advanced mutation transforms are currently gated off in the engine config.

Practical meaning: framework and controls exist, but not every planned
transformation is active by default.

## 8) Is memory security implemented?

Partially, with two layers:

1. Active VM path: object encryption/decryption via `mutil.EncryptObject` and
   `mutil.DecryptObject` in runtime storage/use paths.
2. Additional wrappers: `object/secure_memory.go` provides
   SecureGlobal/SecureStack/SecureConstantPool primitives.

Important: secure_memory wrappers are available utilities, not the primary VM
storage path today.

## 9) How does tamper policy work?

Policy input:

1. `MUTANT_TAMPER_RESPONSE` = `warn`, `delay`, or `terminate`
2. `MUTANT_TAMPER_DELAY_MS` for delay mode
3. `MUTANT_PROTECTION_PROFILE` (`minimal`, `standard`, `paranoid`) for defaults

Precedence:

1. Explicit env override wins.
2. Profile controls defaults.

## 10) What telemetry is available?

Key counters include:

1. debugger_detected
2. sandbox_detected
3. process_protection_detected
4. integrity_failed
5. signature_failed
6. anti_tamper_probe_invoked
7. anti_tamper_probe_error
8. command_attempt, command_blocked, command_succeeded, command_failed

Export:

1. Set `MUTANT_SECURITY_TELEMETRY_FILE` to export JSON at process exit.
2. Set `MUTANT_SECURITY_AUDIT=1` for stderr audit lines.

## 11) What should students remember?

1. Mutant security is policy-driven, not hardcoded to always kill the process.
2. Probes are evidence producers; runner decides enforcement.
3. Mode/profile/env combinations matter as much as cryptography.
4. Read confidence + detail together before drawing conclusions.
