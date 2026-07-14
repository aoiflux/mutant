package vm

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"mutant/code"
	"mutant/compiler"
	"mutant/mutil"
	"mutant/security"
)

func TestVMIntegrityTamperResponseModes(t *testing.T) {
	t.Run("warn", func(t *testing.T) {
		security.ResetSecurityTelemetry()
		vm := tamperedVMForPolicyTest()
		vm.secureMode = false

		err := vm.verifyCurrentFrameIntegrity()
		if err != nil {
			t.Fatalf("expected warn mode to continue, got: %v", err)
		}

		snapshot := security.SecurityTelemetrySnapshot()
		if snapshot["integrity_failed"] == 0 {
			t.Fatalf("expected integrity failure telemetry increment in warn mode")
		}
	})

	t.Run("terminate", func(t *testing.T) {
		security.ResetSecurityTelemetry()
		vm := tamperedVMForPolicyTest()

		err := vm.verifyCurrentFrameIntegrity()
		if err == nil {
			t.Fatalf("expected terminate mode to fail on integrity tamper")
		}

		snapshot := security.SecurityTelemetrySnapshot()
		if snapshot["integrity_failed"] == 0 {
			t.Fatalf("expected integrity failure telemetry increment in terminate mode")
		}
	})
}

func tamperedVMForPolicyTest() *VM {
	bc := &compiler.ByteCode{Instructions: []byte{0x42}}
	vm := New(bc)
	frame := vm.currentFrame()
	frame.cl.Fn.Instructions[0] ^= 0xFF
	return vm
}

func TestValidateSecurityCheckOpcodesPresent(t *testing.T) {
	ins := append(code.Make(code.OpChkDbg), code.Make(code.OpChkSnd)...)
	ins = append(ins, code.Make(code.OpNull)...)

	bc := &compiler.ByteCode{Instructions: ins}
	encrypted := mutil.EncryptByteCode(bc, "testpwd")
	vm := NewWithPassword(encrypted, "testpwd")

	if err := vm.validateSecurityCheckOpcodes("before-execution"); err != nil {
		t.Fatalf("expected required security opcodes to be present: %v", err)
	}
}

func TestValidateSecurityCheckOpcodesMissing(t *testing.T) {
	bc := &compiler.ByteCode{Instructions: code.Make(code.OpNull)}
	encrypted := mutil.EncryptByteCode(bc, "testpwd")
	vm := NewWithPassword(encrypted, "testpwd")

	err := vm.validateSecurityCheckOpcodes("before-execution")
	if err == nil {
		t.Fatalf("expected missing security opcode validation error")
	}

	if !strings.Contains(err.Error(), "required security check opcodes missing") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestVMDevModeWarnsOnSecurityOpcodes(t *testing.T) {
	prevDebugger := isDebuggerPresent
	prevSandbox := isSandboxed
	prevLogger := logSecurityWarning
	defer func() {
		isDebuggerPresent = prevDebugger
		isSandboxed = prevSandbox
		logSecurityWarning = prevLogger
	}()

	isDebuggerPresent = func() bool { return true }
	isSandboxed = func() bool { return true }

	var warnings bytes.Buffer
	logSecurityWarning = func(event, stage string) {
		_, _ = io.WriteString(&warnings, event+":"+stage+"\n")
	}

	ins := append(code.Make(code.OpChkDbg), code.Make(code.OpChkSnd)...)
	ins = append(ins, code.Make(code.OpNull)...)

	bc := &compiler.ByteCode{Instructions: ins}
	encrypted := mutil.EncryptByteCode(bc, "testpwd")
	vm := NewWithPasswordMode(encrypted, "testpwd", false)

	if err := vm.Run(); err != nil {
		t.Fatalf("expected dev mode VM to continue, got: %v", err)
	}

	if got := warnings.String(); !strings.Contains(got, "debugger_detected:vm-run") || !strings.Contains(got, "sandbox_detected:vm-run") {
		t.Fatalf("expected warning log entries, got: %q", got)
	}
}

func TestIntegrityProbeScheduleAdvancesWithinBounds(t *testing.T) {
	bc := &compiler.ByteCode{Instructions: append(code.Make(code.OpChkDbg), code.Make(code.OpChkSnd)...)}
	vm := New(bc)

	if vm.nextIntegrityAt != 0 {
		t.Fatalf("expected first integrity probe at step 0, got %d", vm.nextIntegrityAt)
	}

	if vm.nextSweepAt < integritySweepBase || vm.nextSweepAt >= integritySweepBase+integritySweepSpread {
		t.Fatalf("unexpected initial sweep schedule: %d", vm.nextSweepAt)
	}

	firstProbe := vm.nextProbeInterval()
	if firstProbe < vm.integrityEvery || firstProbe >= vm.integrityEvery+integrityProbeSpread {
		t.Fatalf("probe interval out of bounds: %d", firstProbe)
	}

	firstSweep := vm.nextSweepInterval()
	if firstSweep < integritySweepBase || firstSweep >= integritySweepBase+integritySweepSpread {
		t.Fatalf("sweep interval out of bounds: %d", firstSweep)
	}

	secondProbe := vm.nextProbeInterval()
	if secondProbe < vm.integrityEvery || secondProbe >= vm.integrityEvery+integrityProbeSpread {
		t.Fatalf("second probe interval out of bounds: %d", secondProbe)
	}

	if firstProbe == secondProbe && integrityProbeSpread > 1 {
		t.Fatalf("expected probe schedule to advance, got repeated interval %d", firstProbe)
	}
}

func TestControlFlowIntegrityRejectsInvalidInstructionPointer(t *testing.T) {
	security.ResetSecurityTelemetry()

	bc := &compiler.ByteCode{Instructions: append(code.Make(code.OpConstant, 0), code.Make(code.OpNull)...)}
	encrypted := mutil.EncryptByteCode(bc, "testpwd")
	vm := NewWithPasswordMode(encrypted, "testpwd", true)
	vm.currentFrame().ip = 1

	err := vm.runIntegrityProbes()
	if err == nil {
		t.Fatalf("expected invalid instruction pointer to fail control-flow integrity")
	}

	snapshot := security.SecurityTelemetrySnapshot()
	if snapshot["integrity_failed"] == 0 {
		t.Fatalf("expected integrity failure telemetry increment for control-flow violation")
	}
}

func TestControlFlowIntegrityAllowsInitialFrameSentinel(t *testing.T) {
	security.ResetSecurityTelemetry()

	bc := &compiler.ByteCode{Instructions: append(code.Make(code.OpConstant, 0), code.Make(code.OpNull)...)}
	encrypted := mutil.EncryptByteCode(bc, "testpwd")
	vm := NewWithPasswordMode(encrypted, "testpwd", true)

	err := vm.runIntegrityProbes()
	if err != nil {
		t.Fatalf("expected initial frame sentinel ip to be accepted, got: %v", err)
	}

	snapshot := security.SecurityTelemetrySnapshot()
	if snapshot["integrity_failed"] != 0 {
		t.Fatalf("expected no integrity failure telemetry for initial sentinel ip")
	}
}
