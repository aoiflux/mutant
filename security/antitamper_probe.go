package security

import (
	"strings"
)

var antiTamperProbeEnabled = true

func SetAntiTamperProbeEnabledForTesting(enabled bool) {
	antiTamperProbeEnabled = enabled
}

type AntiTamperSignal struct {
	Name       string
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

func makeSignal(name string, detected bool, confidence int, detail string) AntiTamperSignal {
	return AntiTamperSignal{
		Name:       name,
		Detected:   detected,
		Confidence: confidence,
		Detail:     detail,
	}
}
