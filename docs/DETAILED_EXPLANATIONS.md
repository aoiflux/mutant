# Detailed Security Explanations (Current Behavior)

This document explains the main security building blocks in simple language.

## 1. Policy-driven security

Mutant does not hardcode one response for all detections.

1. A detector raises an event or signal.
2. Policy decides action using mode/profile/env configuration.
3. Action can be warn, delay, or terminate.

Why this is useful:

1. Production can fail closed.
2. Development can stay usable.
3. Same detection logic works across environments.

## 2. Staged anti-reversing checks

Runner checks happen at two stages:

1. pre-decode
2. pre-execution

At each stage:

1. anti-debug check
2. sandbox check
3. process-protection check (if probe gate and process-protection gate allow it)

This catches tampering both before decode and before VM execution.

## 3. Anti-tamper probes: signal model

Each probe returns:

1. name
2. detected
3. confidence
4. detail

Important idea:

1. Probe signals are evidence.
2. Enforcement is caller logic (runner path).
3. Builtin diagnostics can request broader probes for visibility.

## 4. Process-protection logic

Runner process-protection uses a focused probe set and thresholding:

1. process_injection
2. trampoline
3. iat_got
4. module_integrity
5. memory_page_anomaly

Enforcement trigger:

1. detected=true and confidence >= 80

## 5. Polymorphic engine status

Current status is mixed by design:

1. Engine integration exists.
2. Mutation controls are wired.
3. Marker/tagging is active.
4. Advanced transforms are currently gated for safety and compatibility.

See full status and roadmap:

1. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)

## 6. Memory hardening status

Current runtime path:

1. VM uses object-level encryption/decryption utilities in storage/use path.

Additional primitives available:

1. SecureGlobal
2. SecureStack
3. SecureConstantPool

These wrappers exist and are useful, but are not the only active runtime
mechanism.

## 7. Why confidence matters

Single signals can be noisy.

Using confidence and detail together helps:

1. reduce false positives
2. explain why an action happened
3. support incident triage and telemetry analysis

## 8. Where to go next

1. [SECURITY_LLD](SECURITY_LLD.md)
2. [SECURITY_DIAGRAMS](SECURITY_DIAGRAMS.md)
3. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
4. [PROCESS_INJECTION_DETECTION_LLD](PROCESS_INJECTION_DETECTION_LLD.md)
