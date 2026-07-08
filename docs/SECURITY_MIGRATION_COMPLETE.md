# Security Migration Status (Current)

This file is the current migration snapshot for Mutant security architecture.

## 1. Migration Goal

Move from basic protection to policy-driven, code-signed, telemetry-visible
runtime security with staged enforcement.

## 2. Completed Migration Areas

### 2.1 Core Runtime Security

1. Signed artifact verification integrated with runner.
2. Tamper response policy abstraction in place.
3. Secure/compat/dev posture handling implemented.
4. Protection profile defaulting implemented.

### 2.2 Anti-Reverse Engineering Pipeline

1. Anti-debug checks integrated at pre-decode and pre-execution stages.
2. Sandbox detection integrated at pre-decode and pre-execution stages.
3. Anti-tamper probe framework integrated and callable from runner and builtins.

### 2.3 Process Protection

1. Runner process-protection enforcement path implemented.
2. Windows-specific process protection probes implemented.
3. Confidence thresholding for enforcement implemented (`>= 80`).
4. Probe and process-protection telemetry counters implemented.

### 2.4 Runtime Integrity

1. VM integrity baseline registration implemented.
2. Periodic/jitter/sweep integrity checks implemented.
3. Integrity failure policy and telemetry path implemented.

## 3. Partially Completed Areas

### 3.1 Polymorphic Engine

1. Engine integration and marker flow are implemented.
2. CLI mutation level and seed are integrated.
3. Advanced transform set is currently gated in config.

### 3.2 Memory Hardening

1. VM runtime uses mutil object encrypt/decrypt storage path.
2. Additional secure wrappers are available in `object/secure_memory.go`.
3. Wrapper-first VM wiring is not the default path yet.

## 4. Remaining Migration Backlog

### 4.1 Probe Depth and Correlation

1. Optional cross-process visibility (with sufficient privileges).
2. Multi-signal weighted correlator for reduced false positives.
3. Allowlist tuning for operational environments.

### 4.2 Polymorphic Completion

1. Enable advanced transforms with VM-safe compatibility checks.
2. Strengthen deterministic seed reproducibility tests.
3. Add stability/performance gates in CI.

### 4.3 Documentation and Operations

1. Keep enablement gates and enforcement gates clearly separated in docs.
2. Keep runbook and LLD traceability aligned with runner behavior.
3. Add student-friendly diagrams and quick-reference paths.

## 5. Migration Health Summary

1. Core security migration: complete.
2. Enforcement architecture: complete.
3. Advanced obfuscation depth: partial.
4. Advanced process-protection depth: partial.
5. Operational clarity and docs: now synchronized with code baseline.
