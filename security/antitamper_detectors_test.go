package security

import "testing"

func TestMakeSignalFields(t *testing.T) {
	signal := makeSignal(ProbeTiming, true, ConfidenceTimingSuspicious, "detail")

	if signal.Name != ProbeTiming {
		t.Fatalf("unexpected signal name: got=%q want=%q", signal.Name, ProbeTiming)
	}
	if !signal.Detected {
		t.Fatalf("expected detected=true")
	}
	if signal.Confidence != ConfidenceTimingSuspicious {
		t.Fatalf("unexpected confidence: got=%d want=%d", signal.Confidence, ConfidenceTimingSuspicious)
	}
	if signal.Detail != "detail" {
		t.Fatalf("unexpected detail: got=%q", signal.Detail)
	}
}

func TestProbeOneUnknownAndEmpty(t *testing.T) {
	empty := probeOne("")
	if empty.Name != "" {
		t.Fatalf("expected empty name for empty probe, got %q", empty.Name)
	}
	if empty.Detected {
		t.Fatalf("expected empty probe to be not detected")
	}
	if empty.Confidence != ConfidenceNone {
		t.Fatalf("expected confidence=%d, got %d", ConfidenceNone, empty.Confidence)
	}
	if empty.Detail != AntiTamperDetailUnknownProbe {
		t.Fatalf("expected detail=%q, got %q", AntiTamperDetailUnknownProbe, empty.Detail)
	}

	unknown := probeOne("unknown_probe")
	const unknownProbeName = "unknown_probe"
	if unknown.Name != unknownProbeName {
		t.Fatalf("expected passthrough probe name, got %q", unknown.Name)
	}
	if unknown.Detected {
		t.Fatalf("expected unknown probe to be not detected")
	}
	if unknown.Confidence != ConfidenceNone {
		t.Fatalf("expected confidence=%d, got %d", ConfidenceNone, unknown.Confidence)
	}
	if unknown.Detail != AntiTamperDetailUnknownProbe {
		t.Fatalf("expected detail=%q, got %q", AntiTamperDetailUnknownProbe, unknown.Detail)
	}
}

func TestProbeOneNotImplementedSignals(t *testing.T) {
	tests := []string{ProbeACPIPCI, ProbeGPUFeature}

	for _, probe := range tests {
		signal := probeOne(probe)
		if signal.Name != probe {
			t.Fatalf("expected probe name %q, got %q", probe, signal.Name)
		}
		if signal.Detected {
			t.Fatalf("expected probe %q to be not detected", probe)
		}
		if signal.Confidence != ConfidenceNone {
			t.Fatalf("expected probe %q confidence=%d, got %d", probe, ConfidenceNone, signal.Confidence)
		}
		if signal.Detail != AntiTamperDetailNotImplemented {
			t.Fatalf("expected probe %q detail=%q, got %q", probe, AntiTamperDetailNotImplemented, signal.Detail)
		}
	}
}
