package runner

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"mutant/security"
)

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	fn()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = original
	var captured bytes.Buffer
	if _, err := captured.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	return captured.String()
}

// M26-TMP-018. Off Windows, every probe process protection runs answers
// "not supported on this platform", detected false -- and the runner, which
// reads only detected and confidence, passed the stage exactly as it passes a
// clean Windows host. A run whose process protection looked at nothing now says
// so once, and a run where it looked says nothing.
func TestProcessProtectionThatMeasuredNothingSaysSo(t *testing.T) {
	originalProbe := runAntiTamperProbe
	t.Cleanup(func() {
		runAntiTamperProbe = originalProbe
		processProtectionNote = new(sync.Once)
	})

	answer := func(measured bool) {
		runAntiTamperProbe = func(requested []string, stage string) ([]security.AntiTamperSignal, bool, error) {
			signals := make([]security.AntiTamperSignal, 0, len(requested))
			for _, name := range requested {
				signals = append(signals, security.AntiTamperSignal{Name: name, Measured: measured, Detail: "test"})
			}
			return signals, true, nil
		}
		processProtectionNote = new(sync.Once)
	}

	answer(false)
	output := captureStderr(t, func() {
		for _, stage := range []string{"pre-decode", "pre-execution"} {
			if err := enforceProcessProtection(true, stage); err != nil {
				t.Fatalf("%s: %v", stage, err)
			}
		}
	})
	if strings.Count(output, "process protection measured nothing") != 1 {
		t.Fatalf("a run whose process protection looked at nothing did not say so exactly once:\n%s", output)
	}

	answer(true)
	if output := captureStderr(t, func() { _ = enforceProcessProtection(true, "pre-decode") }); output != "" {
		t.Fatalf("a run whose process protection looked printed %q", output)
	}
}
