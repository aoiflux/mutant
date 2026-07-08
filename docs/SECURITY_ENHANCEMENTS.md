# Security Enhancements Roadmap (Code-Synced)

This document tracks enhancement work from current implementation to future
hardening.

Status tags:

1. implemented
2. partial
3. planned

## 1. Current Baseline

Implemented now:

1. Signed artifact verification with trusted-key secure path.
2. Tamper response policy (`warn`, `delay`, `terminate`).
3. Protection profiles (`minimal`, `standard`, `paranoid`).
4. Anti-debug checks in runner pre-decode and pre-execution.
5. Sandbox checks in runner pre-decode and pre-execution.
6. Anti-tamper probe framework with confidence-based signals.
7. Windows process-protection probes (process injection, trampoline, iat/got,
   module markers, RWX anomalies).
8. VM integrity probing and telemetry export.

Partial now:

1. Polymorphic engine wiring exists, but advanced transformations are gated in
   current config.
2. Memory-security wrappers exist (`object/secure_memory.go`) but VM primarily
   uses mutil object encryption path.

## 2. Priority Enhancements

### 2.1 Anti-Tamper Quality

Status: partial

Goals:

1. Expand process-protection from self-process heuristics to optional
   cross-process visibility.
2. Improve confidence correlation from per-signal thresholding to weighted
   multi-signal verdicts.
3. Add allowlist support for approved enterprise tooling.

Primary anchors:

1. `security/antitamper_probe.go`
2. `security/antitamper_windows.go`
3. `runner/runner.go`

### 2.2 Polymorphic Engine Completion

Status: partial

Current:

1. Engine and marker pipeline are integrated.
2. Mutation controls are exposed through CLI mutation level/seed.

Planned:

1. Enable safe instruction-boundary aware transforms.
2. Add reversible opcode remap path with VM/runtime compatibility guardrails.
3. Add deterministic reproducibility tests per seed.

Primary anchors:

1. `compiler/polymorphic.go`
2. `compiler/compiler.go`

### 2.3 Memory Hardening Integration

Status: partial

Current:

1. VM uses `mutil.EncryptObject`/`mutil.DecryptObject` for runtime storage/use
   path.
2. Secure wrappers exist but are not the primary runtime path.

Planned:

1. Formalize when to use wrapper-based storage in VM path.
2. Add optional policy gate for higher memory hardening mode.
3. Add benchmark guardrails to keep overhead bounded.

Primary anchors:

1. `vm/vm.go`
2. `mutil/util.go`
3. `object/secure_memory.go`

### 2.4 Probe Enablement UX

Status: planned

Goal:

1. Simplify understanding of probe gates and enforcement gates.

Planned:

1. Keep current gates for compatibility.
2. Add clearer docs and examples for production posture.
3. Consider profile-based default for probe gate in future major release.

Primary anchors:

1. `security/antitamper_probe.go`
2. `runner/runner.go`
3. `security/profile.go`

## 3. Suggested Release Phasing

### Phase A (near-term)

1. Documentation sync and operator clarity.
2. Add targeted tests for probe gate combinations.
3. Add clearer telemetry explanations in runbook.

### Phase B (mid-term)

1. Complete safe polymorphic transforms rollout.
2. Add stronger anti-tamper correlation logic.
3. Add optional remote process scan in observe mode.

### Phase C (later)

1. Controlled enforcement for remote-process high-confidence verdicts.
2. Expanded policy controls and allowlist tuning.
3. Optional deeper memory hardening mode for high-security deployments.

## 4. Student Summary

1. Core security is already active and usable today.
2. Most future work is quality and depth, not basic capability.
3. The important engineering challenge is balancing security coverage, false
   positives, and runtime overhead.
