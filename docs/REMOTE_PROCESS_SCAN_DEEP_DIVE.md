# Remote Process Scan Deep Dive

## 1. Scope

This document describes the current remote process scan architecture and
integration points.

It covers:

1. Config and mode gates.
2. Verdict correlation model.
3. Telemetry and runner enforcement behavior.
4. Current implementation depth and next hardening steps.

Primary implementation anchors:

1. `security/processscan_types.go`
2. `security/processscan_config.go`
3. `security/processscan_correlator.go`
4. `security/processscan_manager.go`
5. `security/processscan_windows.go`
6. `runner/runner.go`

## 2. Control Surface

**There is none.** Remote process scanning is off in every shipped binary and
cannot be turned on from outside the process. The whole model lives in
`remoteScanConfigState`, a package-level `RemoteScanConfig` in
`security/processscan_config.go`, written only by
`SetRemoteScanConfigForTesting`. Mutant takes no configuration from environment
variables, and no flag has been added for this subsystem yet. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

The fields, and what they hold in a shipped binary:

1. `Enabled` -- `false`. Master gate for manager execution.
   `isRemoteProcessScanEnabled()` returns it, so `RunRemoteProcessScan` reports
   `enabled=false` and the runner skips enforcement entirely.

2. `Mode` -- `observe`.

- `off`: disabled path.
- `observe`: telemetry only.
- `enforce`: policy block on critical verdict.

`ResolveRemoteScanConfig` coerces any unrecognised value back to `observe`.

3. `MaxProcesses` -- `32`.

4. `IntervalMs` -- `1000`.

5. `Allowlist` -- empty. Process names to skip;
   `parseRemoteProcessAllowlist` has no source to read from and returns an empty
   set. It remains as the seam a future `--scan-allowlist <file>` would fill.

6. `HighRiskScore` / `CriticalScore` -- `70` / `85`. `ResolveRemoteScanConfig`
   raises `CriticalScore` to `HighRiskScore` if a caller sets them inverted.

The `Enabled: true` paths documented in the rest of this file are exercised by
tests, which set the config directly. They are not reachable by an operator.

## 3. Data Model

Core types:

1. `RemoteProcessTarget`

- `PID`, `Name`, `Executable`

2. `RemoteProcessSignal`

- `Name`, `Detected`, `Weight`, `Confidence`, `Detail`, `Evidence`

3. `ProcessRiskVerdict`

- `PID`, `Name`, `FinalScore`, `RiskBand`, `Signals`

4. `RemoteScanConfig`

- gate flags, thresholds, scope tuning, and allowlist

## 4. Correlation Logic

`CorrelateProcessSignals` rules:

1. Sum only weights where `Detected=true`.
2. Cap final score at `100`.
3. Assign risk band from score:

- `<40` -> `low`
- `40..69` -> `medium`
- `70..84` -> `high`
- `>=85` -> `critical`

Normalization behavior:

1. If scanner returns verdicts with raw signals but no score, manager computes
   normalized score and band.
2. If scanner already returns score-only verdicts, manager preserves score and
   backfills risk band.

## 5. Manager Execution Flow

`RunRemoteProcessScan(stage)` behavior:

1. Resolve config from env.
2. Exit with `enabled=false` when disabled or mode is `off`.
3. Record invocation telemetry.
4. Execute platform scanner (`scanRemoteProcesses`).
5. On scanner error:

- Record `remote_process_scan_error` telemetry.
- Return error with `enabled=true`.

6. Normalize verdicts and emit score-band telemetry.

Telemetry events emitted by manager:

1. `remote_process_scan_invoked`
2. `remote_process_scan_error`
3. `remote_process_suspicious`
4. `remote_process_critical`

## 6. Runner Enforcement Semantics

Runner path:

1. Called in anti-rev pipeline after local process protection probes.
2. Executed at both `pre-decode` and `pre-execution` stages.

Decision behavior:

1. `observe` mode:

- Never blocks execution.
- Keeps telemetry for visibility.

2. `enforce` mode:

- Blocks only when any verdict score is `>= CriticalScore`.
- High but non-critical verdicts are advisory.

3. Scanner errors:

- Non-blocking.
- Still counted in telemetry.

## 7. Current Implementation Depth

Implemented:

1. Types/config parsing with safe defaults.
2. Correlator and risk-band mapping.
3. Telemetry integration.
4. Runner observe/enforce policy integration.
5. Unit coverage for config, correlator, manager, and runner behavior.

Current limitation:

1. `ScanRemoteProcessesWindows` is currently a safe no-op returning `nil, nil`.
2. This means manager and policy plumbing are production-wired, while detector
   signal depth is not yet implemented.

## 8. Hardening Backlog

Recommended next increments:

1. Implement Windows process enumeration and target filtering.
2. Add module/memory/thread/hook inspectors that emit weighted signals.
3. Add score calibration fixtures to control false positives.
4. Extend coverage with platform-specific integration tests.
5. Add per-verdict evidence export path for incident workflows.
