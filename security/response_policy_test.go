package security

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	os.Stderr = writer
	defer func() {
		os.Stderr = originalStderr
	}()

	// Drained concurrently with fn: a pipe holds only a few kilobytes (4 KiB on
	// Windows), so reading only after fn returns deadlocks once the captured
	// output outgrows the buffer.
	captured := make(chan string, 1)
	go func() {
		output, readErr := io.ReadAll(reader)
		if readErr != nil {
			captured <- ""
			return
		}
		captured <- string(output)
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	return <-captured
}

// Every terminating security event has to name the detector, the reason and a
// remedy -- that is M-7's acceptance test, and the reason it exists is that the
// message it replaces ("sandbox detected, execution halted for security") named
// none of the three. This walks the whole event set rather than a sample,
// because an event added later with no guidance entry would print an action
// line and nothing else, which is the state this item was opened to fix.
func TestEveryTerminatingEventPrintsDetectorReasonAndRemedy(t *testing.T) {
	events := []string{
		"sandbox_detected",
		"debugger_detected",
		"process_protection_detected",
		"remote_process_protection_detected",
		"signature_failed",
		"integrity_failed",
		"lua_patch_failed",
	}

	for _, event := range events {
		t.Run(event, func(t *testing.T) {
			output := captureStderr(t, func() {
				ExplainTamperTermination(event, "test-stage", TamperDetail{
					Detector:   "test-detector",
					Kind:       "test-kind",
					Confidence: 91,
					Signals:    []string{"first", "second"},
				})
			})

			for _, want := range []string{
				"event=" + event,
				"stage=test-stage",
				"action=terminate",
				"detector=test-detector",
				"type=test-kind",
				"confidence=91",
				"signals=first,second",
				"reason:",
				"remedy:",
			} {
				if !strings.Contains(output, want) {
					t.Fatalf("expected %q in the explanation, got:\n%s", want, output)
				}
			}
		})
	}
}

// --compat is the supported answer to a probe that fired on an ordinary
// container, VM or CI runner. It is not an answer to an artifact that fails its
// own signature or integrity check: there, it would only downgrade the finding
// to a warning and run the file anyway. Naming it would be advice to ignore the
// one thing the check exists to report.
func TestOnlyHostProbeEventsNameCompatAsTheRemedy(t *testing.T) {
	probeEvents := []string{
		"sandbox_detected",
		"debugger_detected",
		"process_protection_detected",
		"remote_process_protection_detected",
	}
	artifactEvents := []string{"signature_failed", "integrity_failed", "lua_patch_failed"}

	for _, event := range probeEvents {
		output := captureStderr(t, func() {
			ExplainTamperTermination(event, "test-stage", TamperDetail{})
		})
		if !strings.Contains(output, "--compat") {
			t.Fatalf("expected %s to name --compat, got:\n%s", event, output)
		}
	}

	for _, event := range artifactEvents {
		output := captureStderr(t, func() {
			ExplainTamperTermination(event, "test-stage", TamperDetail{})
		})
		if strings.Contains(output, "re-run with --compat") {
			t.Fatalf("%s must not offer --compat as the remedy, got:\n%s", event, output)
		}
	}
}

// A detector that does not classify or does not score must print neither, rather
// than an empty type= and a confidence=0 that reads as a real reading of zero.
func TestDetailOmitsFieldsTheDetectorDidNotFillIn(t *testing.T) {
	output := captureStderr(t, func() {
		ExplainTamperTermination("debugger_detected", "vm-run", TamperDetail{
			Detector: "debugger",
			Signals:  []string{"windows:is_debugger_present"},
		})
	})

	if !strings.Contains(output, "detector=debugger signals=windows:is_debugger_present") {
		t.Fatalf("expected a detector line with only the fields that were set, got:\n%s", output)
	}
	if strings.Contains(output, "type=") || strings.Contains(output, "confidence=") {
		t.Fatalf("expected no empty type/confidence fields, got:\n%s", output)
	}
}

// An event with no detector behind it still explains itself; there is simply no
// detector line to print.
func TestZeroDetailStillExplainsTheEvent(t *testing.T) {
	output := captureStderr(t, func() {
		ExplainTamperTermination("signature_failed", "secure-mode-verify", TamperDetail{})
	})

	if strings.Contains(output, "detector=") {
		t.Fatalf("expected no detector line for a zero detail, got:\n%s", output)
	}
	if !strings.Contains(output, "reason:") || !strings.Contains(output, "remedy:") {
		t.Fatalf("expected reason and remedy without a detector, got:\n%s", output)
	}
}

// The warn path stays one line. It is reached from inside the VM's instruction
// stream, once per injected check a program runs through, so a four-line block
// there would print the same paragraph dozens of times in a single run. A
// termination happens once, because the run ends.
func TestWarnAndDelayPathsStayOneLine(t *testing.T) {
	output := captureStderr(t, func() {
		if err := ApplyTamperResponseWithDetail(
			"sandbox_detected", "vm-run", false, ErrSandboxDetected,
			TamperDetail{Detector: "sandbox", Kind: "docker", Confidence: 90},
		); err != nil {
			t.Fatalf("expected warn to continue, got: %v", err)
		}
	})

	if lines := strings.Count(strings.TrimSpace(output), "\n"); lines != 0 {
		t.Fatalf("expected the warn path to print exactly one line, got:\n%s", output)
	}
	if !strings.Contains(output, "action=warn") {
		t.Fatalf("expected the warn line, got:\n%s", output)
	}
}

// Terminating still returns the caller's error: the explanation is printed
// alongside it, never in place of it, so the exit reason is unchanged.
func TestTerminationStillReturnsTheUnderlyingError(t *testing.T) {
	var err error
	output := captureStderr(t, func() {
		err = ApplyTamperResponseWithDetail(
			"sandbox_detected", "pre-decode", true, ErrSandboxDetected, SandboxTamperDetail())
	})

	if !errors.Is(err, ErrSandboxDetected) {
		t.Fatalf("expected ErrSandboxDetected, got: %v", err)
	}
	if !strings.Contains(output, "action=terminate") {
		t.Fatalf("expected the termination to be explained, got:\n%s", output)
	}
}
