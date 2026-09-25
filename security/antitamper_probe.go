package security

import (
	"strings"
)

var antiTamperProbeEnabled = true

func SetAntiTamperProbeEnabledForTesting(enabled bool) {
	antiTamperProbeEnabled = enabled
}

type AntiTamperSignal struct {
	Name string
	// Measured says the probe ran on this host and looked. A probe that cannot
	// run here -- one that reads Windows process structures, on Linux -- or
	// whose own check failed answers Measured false, and its Detected false is
	// then not a finding: "not detected" and "not looked for" are two answers.
	Measured   bool
	Detected   bool
	Confidence int
	Detail     string
}

func RunAntiTamperProbe(requested []string, stage string) ([]AntiTamperSignal, bool, error) {
	if strings.TrimSpace(stage) == "" {
		stage = AntiTamperUnknownStage
	}

	if !isAntiTamperProbeEnabled() {
		return nil, false, nil
	}

	RecordProbeInvoked(stage)

	signals := runNativeProbe(requested)
	return signals, true, nil
}

func isAntiTamperProbeEnabled() bool {
	return antiTamperProbeEnabled
}

func runNativeProbe(requested []string) []AntiTamperSignal {
	if len(requested) == 0 {
		return nil
	}

	out := make([]AntiTamperSignal, 0, len(requested))
	for _, name := range requested {
		out = append(out, probeOne(strings.TrimSpace(name)))
	}
	return out
}

// makeSignal is a probe's answer when it looked.
func makeSignal(name string, detected bool, confidence int, detail string) AntiTamperSignal {
	return AntiTamperSignal{
		Name:       name,
		Measured:   true,
		Detected:   detected,
		Confidence: confidence,
		Detail:     detail,
	}
}

// unmeasuredSignal is a probe's answer when it did not look, with detail
// saying why. It is never detected and carries no confidence.
func unmeasuredSignal(name, detail string) AntiTamperSignal {
	return AntiTamperSignal{Name: name, Detail: detail}
}
