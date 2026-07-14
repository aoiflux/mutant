# Anti-Tamper Probe Integration

This document explains how anti-tamper probes work today in Mutant, including
the exact enablement gates and how runner enforcement differs from builtin
diagnostic calls.

## 1. Architecture

Core files:

1. `security/antitamper_probe.go` (engine + enablement gate)
2. `security/antitamper_routing.go` (probe dispatch)
3. `security/antitamper_detectors.go` (cross-platform heuristics)
4. `security/antitamper_windows.go` (windows process-protection heuristics)
5. `runner/runner.go` (enforcement)
6. `builtin/security_status.go` (diagnostic exposure)

Telemetry events used by this subsystem:

1. `anti_tamper_probe_invoked`
2. `anti_tamper_probe_error`
3. `process_protection_detected`

## 2. Enablement Model (Important)

Anti-tamper probing has two gates:

1. Master probe gate: `MUTANT_ENABLE_ANTITAMPER_PROBE=1`
2. Runner process-protection gate: `MUTANT_ENABLE_PROCESS_PROTECTION`

Behavior:

1. If gate #1 is not `1`, `RunAntiTamperProbe` returns `enabled=false` and no
   probes run.
2. Gate #2 only matters when gate #1 is enabled and runner enforcement is being
   evaluated.
3. Gate #2 defaults to enabled when unset; disable values are `0`, `false`,
   `off`, `no`.

## 3. Probe Output Shape

Each probe returns one `AntiTamperSignal` with:

1. `name`
2. `detected`
3. `confidence`
4. `detail`

Interpretation:

1. `detected` is evidence for that probe only.
2. `confidence` is a per-probe confidence score, not a global verdict.
3. policy action is decided by caller logic (runner or builtin consumer).

## 4. Implemented Probes (Current)

1. `hardware_breakpoint`
2. `timing`
3. `syscall`
4. `frida_ptrace`
5. `ld_preload`
6. `cpuid_hypervisor`
7. `rdtsc_drift`
8. `acpi_pci`
9. `gpu_feature` (placeholder)
10. `iat_got`
11. `syscall_table`
12. `trampoline`
13. `process_injection`
14. `module_integrity`
15. `memory_page_anomaly`

## 5. Runner Enforcement vs Builtin Diagnostics

Runner enforcement probe set (hardcoded in `runner/runner.go`):

1. `process_injection`
2. `trampoline`
3. `iat_got`
4. `module_integrity`
5. `memory_page_anomaly`

Runner threshold:

1. any signal with `detected=true` and `confidence >= 80` triggers
   `process_protection_detected` policy flow.

Builtin diagnostics (`builtin/security_status.go`) use broader probe sets for
visibility and troubleshooting. This is expected and independent of runner
enforcement scope.

## 6. Platform Notes

Windows:

1. `process_injection` uses environment and tasklist marker heuristics.
2. `trampoline` checks selected API prologues for common hook patterns.
3. `iat_got` checks sensitive export memory ownership against expected module.
4. `module_integrity` checks suspicious loaded module markers.
5. `memory_page_anomaly` checks for RWX pages on sensitive API addresses.

Linux:

1. `frida_ptrace` checks FRIDA env markers and `/proc/self/status` tracer PID.
2. `ld_preload` reports active `LD_PRELOAD` markers.

macOS/unsupported paths:

1. unsupported probes return neutral signals with explanatory detail.

## 7. Student Notes

1. Probe enablement and enforcement are not the same thing.
2. Builtin probe output is diagnostic; runner probe output can become policy
   action.
3. Always read `detail` before acting on a single signal.
