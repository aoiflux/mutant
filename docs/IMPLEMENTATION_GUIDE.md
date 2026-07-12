# Security Implementation Guide (Current + Next Steps)

This guide explains what to implement next without repeating already completed
migrations.

## 1. Current baseline assumptions

Already available in codebase:

1. Signature verification path in runner.
2. Policy layer and protection profiles.
3. Anti-debug and sandbox staged checks.
4. Anti-tamper probe framework and Windows process-protection probes.
5. VM integrity probes and telemetry export.

## 2. Phase A: Documentation and observability hardening

1. Keep all security docs aligned to LLD source-of-truth docs.
2. Add test coverage for probe gate combinations.
3. Add runbook examples for common policy/env combinations.

Suggested files:

1. `security/antitamper_probe_test.go`
2. `runner/runner_test.go`
3. docs updates (already ongoing)

## 3. Phase B: Process-protection depth expansion

Current status:

1. Remote process scan manager integration is implemented.
2. Normalized signal schema, weighted correlator, and risk bands are
   implemented.
3. Runner observe/enforce policy wiring is implemented.

Next steps:

1. Implement windows scanner inspectors (modules/memory/thread/hook signals).
2. Calibrate weights and thresholds using false-positive datasets.
3. Add evidence-rich integration tests for platform-specific scanners.

Suggested file plan:

1. `security/processscan_windows.go`
2. `security/processscan_windows_stub.go`
3. `security/processscan_manager_test.go`
4. `security/processscan_correlator_test.go`
5. `runner/runner_test.go`

Design reference:

1. [PROCESS_INJECTION_DETECTION_LLD](PROCESS_INJECTION_DETECTION_LLD.md)
2. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)

## 4. Phase C: Polymorphic completion

1. Enable safe transform stages incrementally.
2. Add strict semantic-equivalence tests.
3. Add reproducibility tests by seed.
4. Keep fast rollback path if compatibility risk appears.

Suggested files:

1. `compiler/polymorphic.go`
2. `compiler/polymorphic_test.go`
3. `compiler/opcode_mapping_test.go`

Design reference:

1. [POLYMORPHIC_BYTECODE_LLD](POLYMORPHIC_BYTECODE_LLD.md)

## 5. Phase D: Memory hardening integration clarity

1. Define wrapper-usage strategy and policy gate.
2. Benchmark wrapper path versus current VM object path.
3. Keep default path performance-safe.

Suggested files:

1. `vm/vm.go`
2. `object/secure_memory.go`
3. `mutil/util.go`

## 6. Verification checklist

1. No doc claims unsupported CLI flags.
2. Probe gate semantics remain explicit everywhere.
3. Runner and builtin probe scope differences are documented.
4. Partial features are marked partial, not complete.
5. Tests cover mode/profile/env combinations.

## 7. Student reading order

1. [SECURITY_ANSWERS](SECURITY_ANSWERS.md)
2. [SECURITY_DIAGRAMS](SECURITY_DIAGRAMS.md)
3. [SECURITY_LLD](SECURITY_LLD.md)
4. [SECURITY_LLD_TRACEABILITY](SECURITY_LLD_TRACEABILITY.md)
