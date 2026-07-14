//go:build windows
// +build windows

package security

import "testing"

func withWindowsProbeMocks(t *testing.T, moduleHandle func(string) uintptr, memoryInfo func(uintptr) (memoryBasicInformation, bool)) {
	t.Helper()
	originalModuleHandle := getModuleHandle
	originalResolveProcAddress := resolveProcAddress
	originalQueryMemoryInfo := queryMemoryInfoAt

	getModuleHandle = moduleHandle
	resolveProcAddress = func(module uintptr, fnName string) uintptr {
		return module + uintptr(len(fnName)+1)
	}
	queryMemoryInfoAt = memoryInfo

	t.Cleanup(func() {
		getModuleHandle = originalModuleHandle
		resolveProcAddress = originalResolveProcAddress
		queryMemoryInfoAt = originalQueryMemoryInfo
	})
}

func TestIsLikelyHookBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{
			name:  "relative jmp hook",
			input: []byte{hookOpcodeRelativeJmp, 0x10, 0x00, 0x00, 0x00, 0x90},
			want:  true,
		},
		{
			name:  "indirect jmp hook",
			input: []byte{hookOpcodeGroup5, hookOpcodeIndirectJmp, 0x10, 0x00, 0x00, 0x00},
			want:  true,
		},
		{
			name:  "movabs jmp hook",
			input: []byte{hookOpcodeRexW, hookOpcodeMovAbsRAX, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, hookOpcodeGroup5, hookOpcodeJmpRAX},
			want:  true,
		},
		{
			name:  "normal prologue",
			input: []byte{0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90},
			want:  false,
		},
		{
			name:  "too short",
			input: []byte{0xE9, 0x01},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyHookBytes(tt.input)
			if got != tt.want {
				t.Fatalf("isLikelyHookBytes()=%t, want=%t", got, tt.want)
			}
		})
	}
}

func TestDetectModuleIntegrity(t *testing.T) {
	withWindowsProbeMocks(
		t,
		func(name string) uintptr {
			switch name {
			case suspiciousModuleNames[0], suspiciousModuleNames[2]:
				return 0x1111
			default:
				return 0
			}
		},
		func(addr uintptr) (memoryBasicInformation, bool) {
			return memoryBasicInformation{}, false
		},
	)

	signal := detectModuleIntegrity()
	if !signal.Detected {
		t.Fatalf("expected module_integrity detected=true")
	}
	if signal.Confidence != ConfidenceModuleIntegrityDetected {
		t.Fatalf("expected confidence=%d, got %d", ConfidenceModuleIntegrityDetected, signal.Confidence)
	}
	if signal.Name != ProbeModuleIntegrity {
		t.Fatalf("expected signal name %s, got %q", ProbeModuleIntegrity, signal.Name)
	}
	if signal.Detail == "" {
		t.Fatalf("expected non-empty detail")
	}
}

func TestDetectMemoryPageAnomaly(t *testing.T) {
	withWindowsProbeMocks(
		t,
		func(name string) uintptr {
			switch name {
			case winModuleNtdll:
				return 0x2000
			case winModuleKernel32:
				return 0x3000
			default:
				return 0
			}
		},
		func(addr uintptr) (memoryBasicInformation, bool) {
			return memoryBasicInformation{Protect: pageExecuteReadWrite}, true
		},
	)

	signal := detectMemoryPageAnomaly()
	if !signal.Detected {
		t.Fatalf("expected memory_page_anomaly detected=true")
	}
	if signal.Confidence != ConfidenceMemoryPageAnomalyDetected {
		t.Fatalf("expected confidence=%d, got %d", ConfidenceMemoryPageAnomalyDetected, signal.Confidence)
	}
	if signal.Name != ProbeMemoryPageAnomaly {
		t.Fatalf("expected signal name %s, got %q", ProbeMemoryPageAnomaly, signal.Name)
	}
	if signal.Detail == "" {
		t.Fatalf("expected non-empty detail")
	}
}

func TestDetectMemoryPageAnomalyNoRWX(t *testing.T) {
	withWindowsProbeMocks(
		t,
		func(name string) uintptr {
			switch name {
			case winModuleNtdll:
				return 0x2000
			case winModuleKernel32:
				return 0x3000
			default:
				return 0
			}
		},
		func(addr uintptr) (memoryBasicInformation, bool) {
			return memoryBasicInformation{Protect: 0x20}, true
		},
	)

	signal := detectMemoryPageAnomaly()
	if signal.Detected {
		t.Fatalf("expected memory_page_anomaly detected=false")
	}
	if signal.Confidence != ConfidenceNone {
		t.Fatalf("expected confidence=%d, got %d", ConfidenceNone, signal.Confidence)
	}
	if signal.Name != ProbeMemoryPageAnomaly {
		t.Fatalf("expected signal name %s, got %q", ProbeMemoryPageAnomaly, signal.Name)
	}
	if signal.Detail != "no rwx api page" {
		t.Fatalf("expected detail no rwx api page, got %q", signal.Detail)
	}
}
