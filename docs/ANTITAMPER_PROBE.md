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

**Both gates are on, always. Neither is configurable.** They used to be
environment variables; Mutant takes no configuration from the environment, and
these are not per-run decisions. See
[CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).

1. Master probe gate: `antiTamperProbeEnabled`
   (`security/antitamper_probe.go`), a package-level `true`.
   `SetAntiTamperProbeEnabledForTesting` exists only so tests can turn probing
   off.
2. Runner process-protection gate: `isProcessProtectionEnabled`
   (`runner/runner.go`), which returns `true`.

Behavior:

1. `RunAntiTamperProbe` returns `enabled=true` and runs the requested probes.
   It returns `enabled=false` only inside a test that has flipped gate #1.
2. Gate #2 governs runner enforcement only. `enforceProcessProtection` consults
   it, then runs the five process-protection probes.
3. What still varies per run is the *response*, not the probing: a signal at
   confidence `>= 80` (`processProtectionTerminateConfidence`) terminates in
   secure mode and warns under `--compat`/`--dev`. See
   [ANTITAMPER_PROBE_ENABLEMENT_LLD.md](ANTITAMPER_PROBE_ENABLEMENT_LLD.md).

## 3. Probe Output Shape

Each probe returns one `AntiTamperSignal` with:

1. `name`
2. `measured`
3. `detected`
4. `confidence`
5. `detail`

Interpretation:

1. `measured` says whether the probe looked. A probe that cannot run on the
   host, or whose own check failed, answers `measured=false`, `detected=false`,
   confidence `0`, and a `detail` saying why. Its `detected=false` is then not
   a finding: "not detected" and "not looked for" are different answers, and
   before 2.6.0 they looked the same.
2. `detected` is evidence for that probe only.
3. `confidence` is a per-probe confidence score, not a global verdict.
4. policy action is decided by caller logic (runner or builtin consumer).

## 4. Implemented Probes (Current)

1. `hardware_breakpoint`
2. `timing`
3. `syscall`
4. `frida_ptrace`
5. `cpuid_hypervisor`
6. `rdtsc_drift`
7. `iat_got`
8. `syscall_table`
9. `trampoline`
10. `process_injection`
11. `module_integrity`
12. `memory_page_anomaly`

Three names were listed here until 2.6.0 and measured nothing, so they are no
longer probes; asking for one returns the `unknown probe` signal.

- `acpi_pci` re-reported the sandbox detector's verdict, which
  `cpuid_hypervisor` already reports, and read no ACPI table or PCI device.
- `gpu_feature` was a placeholder that answered "not implemented yet".
- `ld_preload` answered "env-based preload checks disabled". It could not have
  seen anything: a release is built with `CGO_ENABLED=0` and statically linked,
  so the dynamic loader that `LD_PRELOAD` works through never runs.

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

All five read Windows process structures, so they run on Windows only. On Linux
and macOS every one answers `measured=false`: process protection looks at
nothing there, the stage passes, and the run says so once on stderr --
`[security] process protection measured nothing on linux: ...`.

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

Linux, macOS and anything else:

1. `iat_got`, `syscall_table`, `trampoline`, `process_injection`,
   `module_integrity` and `memory_page_anomaly` answer `measured=false`, with
   `not measured on <os>: this probe reads Windows process structures`.

## 7. Student Notes

1. Probe enablement and enforcement are not the same thing.
2. Builtin probe output is diagnostic; runner probe output can become policy
   action.
3. Always read `detail` before acting on a single signal.
