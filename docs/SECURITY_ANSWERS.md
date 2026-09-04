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
4. Trusted key pinning uses the file named by `--trusted-key <path>`, falling
   back to a locally bootstrapped keypair when the flag is absent.

Compatibility/dev behavior:

1. More permissive by default.
2. The tamper response is `warn` rather than `terminate`. That follows from the
   mode itself -- there is no separate response setting.

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

Important gates -- both are compile-time constants, not settings:

1. `antiTamperProbeEnabled` is `true`, so probes always run.
2. `isProcessProtectionEnabled()` returns `true`, so runner enforcement is
   always active.

Runner enforcement probes:

1. process_injection
2. trampoline
3. iat_got
4. module_integrity
5. memory_page_anomaly

Threshold:

1. `detected=true` with `confidence >= 80` is treated as process protection
   event.

Remote scan status:

1. Remote scan manager integration exists but is off in every shipped binary:
   `remoteScanConfigState.Enabled` is `false` and only tests can change it.
2. The manager supports `off|observe|enforce` mode, defaulting to `observe`.
3. The current Windows scanner is a scaffolding-safe no-op, so integration is
   present while detector depth is still partial.

## 7) Are polymorphic mutations fully active?

Yes, for every transform that exists.

Current state:

1. Polymorphic engine is integrated and marker/tagging is active.
2. Mutation level and seed flags are wired through CLI paths.
3. All four transforms -- NOP insertion, dead-code insertion, constant-pool
   randomization and opcode remapping -- run at **any non-zero** mutation level,
   including the CLI default of 5. `--mutation 0` is the only setting that
   leaves the program byte-identical.
4. `ReorderInstructions` has been removed from `MutationConfig`. Reordering a
   stream needs a reverse mapping the VM has no way to carry; leaving the name
   in place made it read as a transform that was merely switched off.

Until this was fixed, constant-pool randomization was the only transform that
ran and it was gated at level 6 while the CLI defaulted to 5 -- so the default
ran the engine and shipped unmutated bytecode. Two builds of the same source at
the default level were byte-identical.

Practical meaning: `mutant gen` and `mutant release` now emit a structurally
different program on every build unless a fixed `--seed` is given, and the same
`--seed` reproduces a build exactly.

## 8) Is memory security implemented?

Partially, with two layers:

1. Active VM path: object encryption/decryption via `mutil.EncryptObject` and
   `mutil.DecryptObject` in runtime storage/use paths.
2. Additional wrappers: `object/secure_memory.go` provides
   SecureGlobal/SecureStack/SecureConstantPool primitives.

Important: secure_memory wrappers are available utilities, not the primary VM
storage path today.

## 9) How does tamper policy work?

Policy input -- one thing only: the execution mode from the command line.

`ResolveTamperResponse(secureMode)` returns:

1. `warn` in dev mode.
2. `warn` when not in secure mode (`--compat`).
3. Otherwise the profile default, which for the fixed `standard` profile is
   `terminate` in secure mode.

There is no precedence chain and no override. The profile is a constant, the
delay is a constant (`DefaultTamperDelayMs = 250`), and `delay` is reachable in
`ApplyTamperResponse` but no mode selects it. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

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

1. `SecurityTelemetrySnapshot()` and `SecurityTelemetryJSON()` read the counters
   in-process; `ExportSecurityTelemetry(path)` writes them to a file.
2. Nothing in the runner calls the exporter, and `auditEvent` is a no-op, so a
   normal run emits no telemetry file and no audit lines.

## 11) What should students remember?

1. Mutant security is policy-driven, not hardcoded to always kill the process --
   but the policy comes from the execution mode on the command line, never from
   the environment.
2. Probes are evidence producers; runner decides enforcement.
3. The mode you pass matters as much as the cryptography, and it is visible in
   the command you ran. That is the point: a run is reproducible from its
   invocation alone.
4. Read confidence + detail together before drawing conclusions.
