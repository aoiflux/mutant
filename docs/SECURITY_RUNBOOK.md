## 1. Purpose

This runbook explains how to triage and respond to Mutant runtime security
events using current code behavior.

### 1.1 Source-of-Truth Alignment

This runbook is operational guidance. When any statement here conflicts with
low-level design, treat the following as authoritative and update this file:

1. [SECURITY_LLD](SECURITY_LLD.md)
2. [SECURITY_LLD_TRACEABILITY](SECURITY_LLD_TRACEABILITY.md)
3. [ANTITAMPER_PROBE_ENABLEMENT_LLD](ANTITAMPER_PROBE_ENABLEMENT_LLD.md)

Alignment rules:

1. Keep mode and policy semantics identical to LLD definitions.
2. Keep environment variable names and defaults identical to implementation.
3. Avoid introducing undocumented flags or implied capabilities.

## 2. Primary Runtime Events

1. signature_failed
2. debugger_detected
3. sandbox_detected
4. process_protection_detected
5. integrity_failed
6. anti_tamper_probe_error
7. command_blocked
8. command_failed

## 3. Key Controls

### 3.1 Policy Controls

1. `MUTANT_TAMPER_RESPONSE` = `warn|delay|terminate`
2. `MUTANT_TAMPER_DELAY_MS` = delay duration (0..5000)
3. `MUTANT_PROTECTION_PROFILE` = `minimal|standard|paranoid`

### 3.2 Probe Controls

1. `MUTANT_ENABLE_ANTITAMPER_PROBE=1` enables anti-tamper probe execution.
2. `MUTANT_ENABLE_PROCESS_PROTECTION` controls runner process-protection
   enforcement when probes are enabled.

### 3.3 Telemetry Controls

1. `MUTANT_SECURITY_AUDIT=1` emits audit lines to stderr.
2. `MUTANT_SECURITY_TELEMETRY_FILE=<path>` exports JSON telemetry snapshot on
   exit.

## 4. First 10 Minutes Checklist

1. Capture stderr output including `[security]` and `[security-audit]` lines.
2. Save telemetry JSON if enabled.
3. Record mode/profile/env values (`MUTANT_*`).
4. Record artifact hash and executable hash.
5. Identify whether event is isolated or fleet-wide.

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
Get-ChildItem Env:MUTANT_* | Out-File "$dir/env.txt"
Get-FileHash .\mutant.exe -Algorithm SHA256 | Out-File "$dir/hashes.txt"
if (Test-Path .\telemetry.json) { Copy-Item .\telemetry.json "$dir/telemetry.json" }
```

### 7.2 Linux

```bash
ts=$(date +%Y%m%d-%H%M%S)
dir=incident-$ts
mkdir -p "$dir"
env | grep '^MUTANT_' > "$dir/env.txt"
sha256sum ./mutant > "$dir/hashes.txt"
[ -f ./telemetry.json ] && cp ./telemetry.json "$dir/telemetry.json"
```

## 8. Recovery Rules

1. Recover only from trusted, re-verified artifacts.
2. Do not globally relax policy to solve one false positive.
3. Prefer scoped allowlists and short-lived exceptions.
4. Track post-incident hardening actions in backlog.

## 9. Common Policy and Environment Combinations

Use these presets as starting points. Prefer short-lived overrides and document
every change in incident notes.

### 9.1 Production Strict (Fail Closed)

Use when running trusted release artifacts in production.

```powershell
$env:MUTANT_TAMPER_RESPONSE = "terminate"
$env:MUTANT_PROTECTION_PROFILE = "paranoid"
$env:MUTANT_ENABLE_ANTITAMPER_PROBE = "1"
$env:MUTANT_ENABLE_PROCESS_PROTECTION = "1"
$env:MUTANT_SECURITY_AUDIT = "1"
$env:MUTANT_SECURITY_TELEMETRY_FILE = ".\telemetry.json"
```

### 9.2 Production Standard (Balanced)

Use for broad production rollout with strong defaults and lower friction.

```powershell
$env:MUTANT_TAMPER_RESPONSE = "terminate"
$env:MUTANT_PROTECTION_PROFILE = "standard"
$env:MUTANT_ENABLE_ANTITAMPER_PROBE = "1"
$env:MUTANT_ENABLE_PROCESS_PROTECTION = "1"
$env:MUTANT_SECURITY_AUDIT = "1"
```

### 9.3 Investigation Mode (Delay + Observe)

Use during controlled triage when you need more evidence before termination.

```powershell
$env:MUTANT_TAMPER_RESPONSE = "delay"
$env:MUTANT_TAMPER_DELAY_MS = "1500"
$env:MUTANT_PROTECTION_PROFILE = "standard"
$env:MUTANT_ENABLE_ANTITAMPER_PROBE = "1"
$env:MUTANT_ENABLE_PROCESS_PROTECTION = "1"
$env:MUTANT_SECURITY_AUDIT = "1"
$env:MUTANT_SECURITY_TELEMETRY_FILE = ".\telemetry.json"
```

### 9.4 Compatibility Triage (Temporary)

Use only for short-lived false-positive isolation and root-cause analysis.

```powershell
$env:MUTANT_TAMPER_RESPONSE = "warn"
$env:MUTANT_PROTECTION_PROFILE = "minimal"
$env:MUTANT_ENABLE_ANTITAMPER_PROBE = "1"
$env:MUTANT_ENABLE_PROCESS_PROTECTION = "0"
$env:MUTANT_SECURITY_AUDIT = "1"
```

### 9.5 Probe Off (Debug Baseline)

Use to separate probe-related signals from other runtime controls.

```powershell
$env:MUTANT_ENABLE_ANTITAMPER_PROBE = "0"
$env:MUTANT_ENABLE_PROCESS_PROTECTION = "0"
$env:MUTANT_TAMPER_RESPONSE = "warn"
```

### 9.6 Linux Example (Strict)

```bash
export MUTANT_TAMPER_RESPONSE=terminate
export MUTANT_PROTECTION_PROFILE=paranoid
export MUTANT_ENABLE_ANTITAMPER_PROBE=1
export MUTANT_ENABLE_PROCESS_PROTECTION=1
export MUTANT_SECURITY_AUDIT=1
export MUTANT_SECURITY_TELEMETRY_FILE=./telemetry.json
```

### 9.7 Reset to Defaults

```powershell
Remove-Item Env:MUTANT_TAMPER_RESPONSE -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_TAMPER_DELAY_MS -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_PROTECTION_PROFILE -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_ENABLE_ANTITAMPER_PROBE -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_ENABLE_PROCESS_PROTECTION -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_SECURITY_AUDIT -ErrorAction SilentlyContinue
Remove-Item Env:MUTANT_SECURITY_TELEMETRY_FILE -ErrorAction SilentlyContinue
```
