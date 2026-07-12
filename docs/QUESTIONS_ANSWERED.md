# Questions Answered (Code-Synced)

This document answers common security questions using current implementation
behavior.

## 1. Is anti-debugging implemented?

Yes.

1. Platform-specific detection exists in security package.
2. Runner enforces checks at pre-decode and pre-execution stages.
3. Response is policy-driven (warn, delay, terminate).

## 2. Is process injection detection implemented?

Yes, as part of anti-tamper process-protection probes.

1. Probe execution requires MUTANT_ENABLE_ANTITAMPER_PROBE=1.
2. Runner enforcement path is additionally controlled by
   MUTANT_ENABLE_PROCESS_PROTECTION.
3. High-confidence signals (detected=true and confidence >= 80) trigger
   process_protection_detected policy flow.

Remote scan status:

1. Remote scan manager integration exists behind
   MUTANT_ENABLE_REMOTE_PROCESS_SCAN.
2. Mode gate is MUTANT_REMOTE_SCAN_MODE=off|observe|enforce.
3. Current windows scanner is scaffolding-safe no-op, so integration is present
   while detector depth is still partial.

See:

1. [ANTITAMPER_PROBE](ANTITAMPER_PROBE.md)
2. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
3. [PROCESS_INJECTION_DETECTION_LLD](PROCESS_INJECTION_DETECTION_LLD.md)

## 3. Is polymorphic bytecode fully active?

Partially.

1. Engine integration and marker/tagging are active.
2. Mutation controls and seed controls are wired through compile paths.
3. Advanced transforms are currently gated in configuration for safety.

See:

1. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)

## 4. Does secure mode always enforce trusted signer pinning?

Not always.

1. Secure mode is the default runtime posture.
2. Trusted signer verification runs when `--signer-auth` is enabled.
3. Without `--signer-auth`, secure mode keeps runtime hardening gates but does
   not run signer pinning verification.
4. Trusted key source is MUTANT_TRUSTED_PUBLIC_KEY_HEX (with local bootstrap
   fallback if unset).

## 5. Is memory security implemented?

Partially.

1. VM runtime path uses object encryption/decryption in storage/use flow.
2. Additional secure wrappers exist for SecureGlobal, SecureStack, and
   SecureConstantPool.
3. Wrapper-first runtime path is not the default VM storage path today.

## 6. Which docs should students read first?

1. [SECURITY_ANSWERS](SECURITY_ANSWERS.md)
2. [SECURITY_LLD](SECURITY_LLD.md)
3. [SECURITY_DIAGRAMS](SECURITY_DIAGRAMS.md)
4. [SECURITY_RUNBOOK](SECURITY_RUNBOOK.md)
5. [SECURITY_LLD_TRACEABILITY](SECURITY_LLD_TRACEABILITY.md)

## 7. What changed from older docs?

1. Removed stale claims about unsupported CLI flags and unfinished integrations.
2. Clarified gate semantics for anti-tamper probes.
3. Clarified current polymorphic and memory-security status.
4. Clarified signer-auth semantics and remote scan integration depth.
