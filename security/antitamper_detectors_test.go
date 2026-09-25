package security

import (
	"strings"
	"testing"
)

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

// M26-TMP-001 and M26-TMP-018. Three supported probes measured nothing:
// acpi_pci and gpu_feature were routed to "not implemented yet", and ld_preload
// was hard-wired to "env-based preload checks disabled". And six probes that
// read Windows process structures answer "not supported on this platform"
// everywhere else -- including all five the runner's process protection runs
// -- in the same shape as a clean result, detected false, so off Windows that
// protection passed without looking. A probe now either measured, or says in
// Measured, and in its detail, that it did not; the three names are not probes.
func TestEverySupportedProbeMeasuresOrSaysItDidNot(t *testing.T) {
	for _, name := range AntiTamperSupportedProbes {
		signal := probeOne(name)
		if !signal.Measured {
			if signal.Detected || signal.Confidence != ConfidenceNone || signal.Detail == "" {
				t.Errorf("%s did not measure, and answers %+v", name, signal)
			}
			continue
		}
		detail := strings.ToLower(signal.Detail)
		for _, absent := range []string{"not implemented", "disabled", "placeholder", "not supported", "not measured", AntiTamperDetailUnknownProbe} {
			if strings.Contains(detail, absent) {
				t.Errorf("%s says it measured, and reports %q", name, signal.Detail)
			}
		}
	}
	for _, retired := range []string{"acpi_pci", "gpu_feature", "ld_preload"} {
		for _, name := range AntiTamperSupportedProbes {
			if name == retired {
				t.Errorf("%s is still listed as a supported probe", retired)
			}
		}
		if signal := probeOne(retired); signal.Detail != AntiTamperDetailUnknownProbe || signal.Measured || signal.Detected {
			t.Errorf("%s is still routed, or claims a measurement: %+v", retired, signal)
		}
	}
}
