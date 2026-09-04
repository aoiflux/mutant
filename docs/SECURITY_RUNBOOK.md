# Security Runbook

## 1. Purpose

This runbook explains how to triage and respond to Mutant runtime security
events using current code behavior.

### 1.1 Source-of-Truth Alignment

This runbook is operational guidance. When any statement here conflicts with
low-level design, treat the following as authoritative and update this file:

1. [SECURITY_LLD](SECURITY_LLD.md)
2. [SECURITY_LLD_TRACEABILITY](SECURITY_LLD_TRACEABILITY.md)
3. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)
4. [BINARY_ARTIFACT_SECURITY_DEEP_DIVE](BINARY_ARTIFACT_SECURITY_DEEP_DIVE.md)
5. [REMOTE_PROCESS_SCAN_DEEP_DIVE](REMOTE_PROCESS_SCAN_DEEP_DIVE.md)

Alignment rules:

1. Keep mode and policy semantics identical to LLD definitions.
2. Mutant reads no environment variable for configuration. Every control in this
   runbook is a command-line flag or a fixed default; never document a variable
   as a control. See [CONFIGURATION_POLICY.md](CONFIGURATION_POLICY.md).
3. Avoid introducing undocumented flags or implied capabilities.

## 2. Primary Runtime Events

1. signature_failed
2. debugger_detected
3. sandbox_detected
4. process_protection_detected
5. integrity_failed
6. anti_tamper_probe_error
7. remote_process_scan_error
8. remote_process_suspicious
9. remote_process_critical
10. command_blocked
11. command_failed

## 3. Key Controls

The whole control surface is the command line. There is nothing to set before
a run and nothing to unset after one.

### 3.1 Policy Controls

1. `--secure` (the default) resolves the tamper response to `terminate`.
2. `--compat` resolves it to `warn`.
3. `--dev` implies `--compat`, plus local password fallback.
4. `--signer-auth` / `--no-signer-auth` require or skip trusted signer
   verification in secure mode.
5. `--trusted-key <path>` pins verification to the hex-encoded public key in
   that file. Without it, verification uses a locally bootstrapped keypair,
   which trusts whatever signed the artifact on this host.

The tamper response is a pure function of items 1--3. There is no separate
response selector, no delay tuning (the `delay` response exists but no mode
selects it), and no protection-profile selector: the profile is fixed at
`standard`.

### 3.2 Probe Controls

**None.** Anti-tamper probing and runner process-protection enforcement are both
compile-time `true` and always active. Remote process scanning is off in every
shipped binary and reachable only from tests.

What still varies is the response: a process-protection signal at confidence
`>= 80` terminates in secure mode and warns under `--compat`/`--dev`.

### 3.3 Telemetry Controls

**None.** The audit stream is a no-op (`auditEvent` discards its arguments) and
nothing calls `ExportSecurityTelemetry`, so a run emits no audit lines and
writes no telemetry file. Counters are readable in-process only, through
`SecurityTelemetrySnapshot()` / `SecurityTelemetryJSON()`.

## 4. First 10 Minutes Checklist

1. Capture stderr output including `[security]` lines.
2. **Record the exact command line that was run.** It is the complete record of
   how the run was configured -- nothing is read from the environment or from a
   config file, so the invocation and the artifact together fully determine the
   behaviour.
3. Record artifact hash and executable hash.
4. Identify whether event is isolated or fleet-wide.

## 5. Event-by-Event Triage

### 5.1 signature_failed

1. Verify trusted signer key configuration.
2. Confirm artifact source and release pipeline integrity.
3. In production, keep terminate posture until signer chain is trusted.

### 5.2 debugger_detected

1. Check whether debugger activity is expected for host role.
2. Correlate with signature/integrity/process-protection events.
3. If unexpected in production, isolate and redeploy trusted artifact.

### 5.3 sandbox_detected

1. Confirm host classification (real host vs test sandbox).
2. Validate if sandbox execution was intended.
3. For production, treat unexplained sandbox signals as suspicious.

### 5.4 process_protection_detected

1. Confirm anti-tamper probe gate was enabled.
2. Review probe signal details and confidence values.
3. On repeated high-confidence hits, isolate host and inspect
   instrumentation/hooking context.

### 5.5 integrity_failed

1. Treat as potential active tampering.
2. Isolate host and preserve evidence.
3. Re-run artifact on known-clean host to differentiate artifact vs environment
   compromise.

## 6. Severity Guidance

1. integrity_failed: critical baseline
2. signature_failed: high baseline
3. process_protection_detected: high baseline
4. debugger_detected: medium baseline
5. sandbox_detected: medium baseline
6. anti_tamper_probe_error: low to medium (depends on environment)

Production guidance:

1. Never downgrade integrity failures below high severity.
2. Keep explicit exceptions narrow, temporary, and documented.

## 7. Evidence Collection Snippets

### 7.1 PowerShell

```powershell
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$dir = "./incident-$ts"
New-Item -ItemType Directory -Path $dir | Out-Null
# The command line is the configuration. Capture it, not the environment.
(Get-CimInstance Win32_Process -Filter "Name='mutant.exe'").CommandLine |
    Out-File "$dir/commandline.txt"
Get-FileHash ./mutant.exe -Algorithm SHA256 | Out-File "$dir/hashes.txt"
```

### 7.2 Linux

```bash
ts=$(date +%Y%m%d-%H%M%S)
dir=incident-$ts
mkdir -p "$dir"
# The command line is the configuration. Capture it, not the environment.
ps -ww -o args= -C mutant > "$dir/commandline.txt"
sha256sum ./mutant > "$dir/hashes.txt"
```

## 8. Recovery Rules

1. Recover only from trusted, re-verified artifacts.
2. Do not globally relax policy to solve one false positive.
3. Prefer scoped allowlists and short-lived exceptions.
4. Track post-incident hardening actions in backlog.

## 9. Choosing a Posture

There are no policy presets to copy, because there is nothing to preset. A
posture is a command line:

| Situation | Command |
| --- | --- |
| Production, trusted release artifact | `mutant prog.mu --secure --signer-auth --trusted-key <path>` |
| Production, no pinned signer yet | `mutant prog.mu --secure --signer-auth` |
| Short-lived false-positive triage | `mutant prog.mu --compat` |
| Local development | `mutant prog.mu --dev` |

Notes:

1. `--secure` is the default; naming it explicitly makes the incident note
   unambiguous.
2. `--compat` and `--dev` are the only things that downgrade a tamper response
   from `terminate` to `warn`. Both are visible in the command line, so a
   downgrade can never happen behind an operator's back -- which is why the
   presets this section used to carry no longer exist.
3. There is nothing to reset afterwards. A previous run cannot leave state that
   changes the next one.
4. `--timing` adds per-stage timings on stderr when a run is unexpectedly slow.
