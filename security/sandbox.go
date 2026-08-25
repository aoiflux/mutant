package security

import (
	"runtime"
	"strings"
	"sync"
)

type sandboxDetection struct {
	Type       string
	Confidence int
	Indicators []string
}

const sandboxDetectedThreshold = 70

const (
	sandboxTypeNone    = "none"
	minConfidenceScore = 0
	maxConfidenceScore = 100
)

// IsSandboxed returns true when environment signals indicate a high-confidence
// container, virtualization, or sandboxed runtime.
func IsSandboxed() bool {
	_, confidence, err := DetectSandboxType()
	if err != nil {
		return false
	}
	return confidence >= sandboxDetectedThreshold
}

// DetectSandboxType returns the most likely sandbox type and confidence (0-100).
func DetectSandboxType() (string, int, error) {
	result, err := detectSandbox()
	if err != nil {
		securityDevLogf("sandbox detect error=%v", err)
		return sandboxTypeNone, minConfidenceScore, err
	}
	if result.Confidence < minConfidenceScore {
		result.Confidence = minConfidenceScore
	}
	if result.Confidence > maxConfidenceScore {
		result.Confidence = maxConfidenceScore
	}
	if result.Type == "" || result.Confidence == minConfidenceScore {
		securityDevLogf("sandbox detected=false type=none confidence=0 indicators=")
		return sandboxTypeNone, minConfidenceScore, nil
	}
	securityDevLogf(
		"sandbox detected=%t type=%s confidence=%d indicators=%s",
		result.Confidence >= sandboxDetectedThreshold,
		result.Type,
		result.Confidence,
		strings.Join(result.Indicators, ","),
	)
	return result.Type, result.Confidence, err
}

// GetSandboxIndicators returns normalized detection indicators for audit/logging.
func GetSandboxIndicators() ([]string, error) {
	result, err := detectSandbox()
	if err != nil {
		return nil, err
	}
	if len(result.Indicators) == 0 {
		return nil, nil
	}

	indicators := make([]string, len(result.Indicators))
	copy(indicators, result.Indicators)
	return indicators, nil
}

// Whether this process is running inside a container, VM, or analysis sandbox is
// fixed for its lifetime -- a program does not move between a hypervisor and
// bare metal while it runs -- but establishing it is expensive. On Windows the
// probe shells out to tasklist, three wmic queries, powershell, and four reg
// queries, which together cost about a second.
//
// That cost used to be paid per call, and the VM calls this from its instruction
// stream: OpChkSnd runs security.IsSandboxed() wherever the compiler injected a
// check, so a program's runtime grew by roughly a second for every injected
// check it reached. Detecting once and remembering the answer is both faster and
// more honest about what is being measured.
var (
	sandboxOnce      sync.Once
	sandboxCached    sandboxDetection
	sandboxCachedErr error
)

func detectSandbox() (sandboxDetection, error) {
	sandboxOnce.Do(func() {
		sandboxCached, sandboxCachedErr = detectSandboxUncached()
	})
	// The struct is returned by value; callers that adjust Confidence or read
	// Indicators (which GetSandboxIndicators copies) cannot disturb the cache.
	return sandboxCached, sandboxCachedErr
}

// resetSandboxCache forces the next detection to run for real. Tests that drive
// the platform detectors through different environments need it; nothing in the
// running language does.
func resetSandboxCache() {
	sandboxOnce = sync.Once{}
	sandboxCached = sandboxDetection{}
	sandboxCachedErr = nil
}

func detectSandboxUncached() (sandboxDetection, error) {
	switch runtime.GOOS {
	case "windows":
		return detectSandboxWindows()
	case "linux":
		return detectSandboxLinux()
	case "darwin":
		return detectSandboxDarwin()
	default:
		return sandboxDetection{}, nil
	}
}
