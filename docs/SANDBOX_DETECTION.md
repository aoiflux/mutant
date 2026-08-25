# Sandbox Detection Feature

## Overview

The sandbox detection module identifies containerized and virtualized runtimes
and feeds that signal into the runtime tamper-response pipeline.

Current implementation status:

- API implemented: IsSandboxed, DetectSandboxType, GetSandboxIndicators
- Platform detectors implemented: Windows, Linux, macOS
- Runtime enforcement integrated in bytecode execution path (runner.Run
  pre-execution)
- Telemetry integrated: sandbox_detected counter and audit event

## API

### IsSandboxed() bool

Returns true when detection confidence is greater than or equal to the built-in
threshold (currently 70).

```go
if security.IsSandboxed() {
    // High-confidence sandbox/container/vm signal
}
```

### DetectSandboxType() (string, int, error)

Returns the most likely environment type, confidence in [0, 100], and any error
the platform detector reported.

Behavior:

- Returns ("none", 0, nil) when no signal is present
- Confidence is clamped to [0, 100]
- Type is the highest-scoring class for current platform heuristics

```go
sandboxType, confidence, err := security.DetectSandboxType()
if err == nil && confidence >= 70 {
    log.Printf("detected %s (%d%%)", sandboxType, confidence)
}
```

### GetSandboxIndicators() ([]string, error)

Returns normalized, deduplicated indicator strings used by the detector. The
slice is a copy, so a caller cannot edit what later callers see.

```go
indicators, err := security.GetSandboxIndicators()
if err == nil {
    for _, indicator := range indicators {
        log.Println(indicator)
    }
}
```

## Cost and caching

Detection is expensive. The Windows detector alone spawns `tasklist`, three
`wmic` queries, a `powershell` CIM query, and four `reg query` calls; together
they take about a second. macOS shells out to `ps`, Linux reads a dozen files
under /proc and /sys.

The result is therefore computed once per process and cached. That is safe
because the answer cannot change while the process runs -- a program does not
move between a hypervisor and bare metal mid-execution -- and it is necessary
because the VM calls the detector from its instruction stream (see below), so an
uncached probe charged roughly a second per injected check a program reached.

## Implemented Detection Signals

### Linux

Container and VM heuristics currently include:

- Marker files: /.dockerenv, /run/.containerenv, /proc/xen
- Environment markers: KUBERNETES_SERVICE_HOST, KUBERNETES_SERVICE_PORT
- Cgroup markers from /proc/1/cgroup and /proc/self/cgroup: docker, containerd,
  podman, libpod, crio, kubepods, lxc, systemd patterns
- CPU markers from /proc/cpuinfo: hypervisor, kvm, qemu, vmware, virtualbox, xen
- DMI markers from /sys/class/dmi/id/*: vmware, virtualbox, kvm/qemu, xen,
  hyper-v fingerprints

Potential types include: Docker, Container, Kubernetes, LXC, systemd-nspawn, VM,
KVM/QEMU, VMware, VirtualBox, Xen, Hyper-V

### Windows

VM/sandbox heuristics currently include:

- Driver/library file markers: vmmouse.sys, vmhgfs.sys, VBoxMouse.sys,
  VBoxGuest.sys, xenbus.sys, SbieDll.dll
- Environment markers: SANDBOXIE, CUCKOO, VBOX_INSTALL_PATH
- Process markers from tasklist: vmtoolsd.exe, vmwaretray.exe, vboxservice.exe,
  vboxtray.exe, xenservice.exe, qemu-ga.exe, sbiectrl.exe,
  sandboxiedcomlaunch.exe
- Parent-process and working-directory markers for WSL, and the WDAG account and
  profile path for Windows Sandbox
- CPUID hypervisor vendor leaf
- Baseboard and computer-system manufacturer/model, via wmic with a powershell
  Get-CimInstance fallback
- PnP device names, raw SMBIOS firmware table, and registry markers under
  HKLM\SOFTWARE\Microsoft\VirtualMachine and HKLM\HARDWARE\DESCRIPTION\System\BIOS

Potential types include: VMware, VirtualBox, Xen, KVM/QEMU, Sandboxie, Cuckoo,
Hyper-V, WSL, Windows Sandbox

### macOS

Virtualization/sandbox heuristics currently include:

- Environment markers: APP_SANDBOX_CONTAINER_ID, DYLD_INSERT_LIBRARIES,
  COLIMA_HOME
- Application/file markers: /Applications/VMware Fusion.app,
  /Applications/VirtualBox.app, /Applications/Parallels Desktop.app,
  /Applications/UTM.app, /Users/Shared/Parallels, /opt/homebrew/bin/colima
- Process markers from ps -axo comm: vmware-vmx, vboxservice, vboxclient,
  prl_tools, qemu-system, colima

Potential types include: macOS App Sandbox, Colima, VMware Fusion, VirtualBox,
Parallels, UTM, QEMU

## Runtime Enforcement Integration

Sandbox detection is enforced in runner.Run at pre-execution stage, after decode
and after anti-debug pre-execution check.

Current flow:

1. Signature verification
2. Anti-debug pre-decode
3. Decode/decrypt
4. Anti-debug pre-execution
5. Anti-sandbox pre-execution
6. VM run

Detection is also enforced *inside* the VM: the compiler injects OpChkSnd
instructions, and executing one calls `security.IsSandboxed()`. That is a second
enforcement point, reached however many times the program's control flow reaches
an injected check -- which is why the detector is cached (see "Cost and
caching").

On sandbox detection:

- Event recorded: sandbox_detected
- Base error: ErrSandboxDetected
- Response policy resolved by existing tamper policy mechanism

Default response behavior:

- Secure mode: terminate
- Compat mode: warn
- Override via MUTANT_TAMPER_RESPONSE (warn|delay|terminate)

## Telemetry

Sandbox detection contributes to security telemetry snapshot/export:

- sandbox_detected

Audit stream integration (when MUTANT_SECURITY_AUDIT=1):

- event=sandbox_detected stage=<stage>

Telemetry export file is controlled by:

- MUTANT_SECURITY_TELEMETRY_FILE

## Testing

Relevant tests:

- security package sandbox API contract and telemetry coverage
- runner package anti-sandbox policy behavior (secure terminate, compat warn)

Run:

```bash
go test ./security ./runner
```

## Known Limitations

1. Heuristic coverage is intentionally lightweight and may miss sophisticated
   environments.
2. False positives are possible in legitimate virtualized/containerized
   deployments.
3. Some signals depend on process/file visibility and OS permissions.
4. Confidence scores are heuristic, not cryptographic guarantees.

## Future Enhancements

1. Cloud metadata-based environment detection.
2. Additional sandbox frameworks and emulator fingerprints.
3. Policy controls specific to sandbox events (separate from debugger/integrity
   policies).
4. Configurable confidence threshold for IsSandboxed.
