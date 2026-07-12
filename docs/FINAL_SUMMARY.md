# Final Security Summary (Current State)

This is the consolidated, current-state summary for Mutant security.

## 1. What is fully in place

1. Signed artifact verification paths and secure-mode signer-auth trusted-key
   path.
2. Policy-driven tamper response (warn, delay, terminate).
3. Protection profile defaults (minimal, standard, paranoid).
4. Anti-debug and sandbox enforcement at pre-decode and pre-execution.
5. Anti-tamper probe framework with confidence signals.
6. Windows process-protection probes and runner threshold enforcement.
7. VM runtime integrity probing and telemetry export.
8. Remote process scan manager with runner observe/enforce integration.

## 2. What is partial

1. Polymorphic engine: integrated, but advanced transforms remain gated.
2. Memory hardening: active VM object encryption path plus additional wrapper
   primitives.
3. Remote process scan detector depth: scanner contract/integration implemented,
   windows scanner currently scaffolding-safe no-op.

## 3. Operator-critical gates

1. MUTANT_ENABLE_ANTITAMPER_PROBE=1 controls probe execution.
2. MUTANT_ENABLE_PROCESS_PROTECTION controls runner process-protection
   enforcement once probes are enabled.
3. MUTANT_ENABLE_REMOTE_PROCESS_SCAN and MUTANT_REMOTE_SCAN_MODE control remote
   scan execution and enforcement semantics.
4. --signer-auth enables trusted signer verification in secure mode.
5. MUTANT_TAMPER_RESPONSE and MUTANT_PROTECTION_PROFILE determine policy
   outcomes.

## 4. Student learning path

1. [SECURITY_ANSWERS](SECURITY_ANSWERS.md)
2. [SECURITY_DIAGRAMS](SECURITY_DIAGRAMS.md)
3. [SECURITY_LLD](SECURITY_LLD.md)
4. [PROCESS_INJECTION_DETECTION_LLD](PROCESS_INJECTION_DETECTION_LLD.md)
5. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)

## 5. Source-of-truth docs

1. [SECURITY_LLD](SECURITY_LLD.md)
2. [SECURITY_LLD_TRACEABILITY](SECURITY_LLD_TRACEABILITY.md)
3. [ANTITAMPER_PROBE](ANTITAMPER_PROBE.md)
4. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
5. [BINARY_ARTIFACT_SECURITY_DEEP_DIVE](BINARY_ARTIFACT_SECURITY_DEEP_DIVE.md)
6. [REMOTE_PROCESS_SCAN_DEEP_DIVE](REMOTE_PROCESS_SCAN_DEEP_DIVE.md)
