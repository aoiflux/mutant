package security

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	TamperResponseWarn      = "warn"
	TamperResponseDelay     = "delay"
	TamperResponseTerminate = "terminate"

	DefaultTamperDelayMs = 250
	MinTamperDelayMs     = 0
	MaxTamperDelayMs     = 5000
)

// TamperDetail is what a detector actually observed. It exists so a run that
// stops can name the probe that fired and the signals behind it, rather than
// printing only "sandbox detected, execution halted for security" -- a sentence
// that names no probe, no reason, and no way forward, on a check that fires on
// ordinary containers, VMs and CI runners, which is where this tool runs. (M-7)
//
// The zero value is valid and means the event has no detector behind it. A
// signature that does not verify, or bytecode that fails its own integrity
// check, is a fact about the artifact rather than a reading taken of the host,
// and has nothing to report here.
type TamperDetail struct {
	// Detector names the probe: "sandbox", "debugger", "process-protection".
	Detector string
	// Kind is the detector's own classification of what it found, such as the
	// sandbox type. Empty when the detector does not classify.
	Kind string
	// Confidence is 0-100. Zero means the detector does not score.
	Confidence int
	// Signals are the concrete indicators that fired.
	Signals []string
}

// line renders the detail as one key=value record, omitting every field the
// detector did not fill in: a detector that does not classify or does not score
// should print nothing for those rather than an empty `type=` and a misleading
// `confidence=0`.
func (d TamperDetail) line() string {
	if d.Detector == "" {
		return ""
	}

	parts := []string{"detector=" + d.Detector}
	if d.Kind != "" {
		parts = append(parts, "type="+d.Kind)
	}
	if d.Confidence > 0 {
		parts = append(parts, "confidence="+strconv.Itoa(d.Confidence))
	}
	if len(d.Signals) > 0 {
		parts = append(parts, "signals="+strings.Join(d.Signals, ","))
	}

	return strings.Join(parts, " ")
}

// tamperGuidance is what a terminating event tells the operator: why the run
// stopped, and the supported way forward.
type tamperGuidance struct {
	reason string
	remedy []string
}

// compatRemedy is named by the host-probe events, and only by them.
//
// A probe reports what the machine looks like, and an ordinary container, VM or
// CI runner looks enough like an analysis sandbox to trip one -- which is
// exactly where forensic tooling runs. --compat is the supported answer to that
// false positive, and an operator who is not told its name will find it anyway,
// with less understanding of what they gave up.
//
// The artifact events deliberately do not name it. A signature that does not
// verify, and bytecode that fails its own integrity check, are statements about
// the file; --compat would downgrade them to a warning and run it regardless.
// Printing it there would be advice to ignore the finding.
var compatRemedy = []string{
	"re-run with --compat if this host is expected to look like this.",
	"--compat weakens the response only: a probe hit warns instead of stopping",
	"the run. Your password is still required and the artifact is still verified.",
}

var tamperGuidanceByEvent = map[string]tamperGuidance{
	"sandbox_detected": {
		reason: "secure mode does not run where the host looks like an analysis sandbox",
		remedy: compatRemedy,
	},
	"debugger_detected": {
		reason: "secure mode does not run with a debugger attached to this process",
		remedy: compatRemedy,
	},
	"process_protection_detected": {
		reason: "secure mode does not run with injection or hooking activity in this process",
		remedy: compatRemedy,
	},
	"remote_process_protection_detected": {
		reason: "secure mode does not run while another process on this host scores as hostile",
		remedy: compatRemedy,
	},
	"signature_failed": {
		reason: "the artifact does not match the signature it carries",
		remedy: []string{
			"rebuild it from source, or get a copy from whoever signed it.",
			"--compat is not the remedy: it would run this artifact anyway.",
		},
	},
	"integrity_failed": {
		reason: "the bytecode does not match its own integrity check",
		remedy: []string{
			"rebuild the artifact from source. If a clean build fails the same",
			"way, the file was modified after it was signed.",
		},
	},
	"lua_patch_failed": {
		reason: "an embedded Lua patch failed to apply",
		remedy: []string{"rebuild the artifact from source with a patch that applies."},
	},
}

func ResolveTamperResponse(secureMode bool) string {
	if securityDevModeEnabled() {
		return TamperResponseWarn
	}

	if !secureMode {
		return TamperResponseWarn
	}

	return defaultTamperResponseForProfile(secureMode)
}

func ApplyTamperResponse(event, stage string, secureMode bool, baseErr error) error {
	return ApplyTamperResponseWithDetail(event, stage, secureMode, baseErr, TamperDetail{})
}

// ApplyTamperResponseWithDetail is ApplyTamperResponse for an event that has a
// detector behind it, so a termination can say which probe fired and on what.
func ApplyTamperResponseWithDetail(event, stage string, secureMode bool, baseErr error, detail TamperDetail) error {
	response := ResolveTamperResponse(secureMode)

	switch response {
	case TamperResponseWarn:
		fmt.Fprintf(os.Stderr, "[security] event=%s stage=%s action=warn\n", event, stage)
		return nil
	case TamperResponseDelay:
		time.Sleep(resolveTamperDelay())
		fmt.Fprintf(os.Stderr, "[security] event=%s stage=%s action=delay\n", event, stage)
		return nil
	default:
		ExplainTamperTermination(event, stage, detail)
		if baseErr != nil {
			return baseErr
		}
		return errors.New("security policy violation")
	}
}

// ExplainTamperTermination prints the detector, the reason and the remedy for a
// security event that is about to stop the run. ApplyTamperResponseWithDetail
// calls it on the terminate path; the VM calls it directly, because its security
// opcodes return the error themselves rather than going through the policy.
//
// It prints on termination only. The warn path already prints one line per hit,
// and the VM reaches that path from inside the instruction stream, so attaching
// a four-line block to it would repeat the same paragraph at every injected
// check a program runs through. A termination happens exactly once, because the
// run ends there.
func ExplainTamperTermination(event, stage string, detail TamperDetail) {
	fmt.Fprintf(os.Stderr, "[security] event=%s stage=%s action=terminate\n", event, stage)

	if line := detail.line(); line != "" {
		fmt.Fprintf(os.Stderr, "[security] %s\n", line)
	}

	guidance, ok := tamperGuidanceByEvent[event]
	if !ok {
		return
	}

	fmt.Fprintf(os.Stderr, "[security] reason: %s\n", guidance.reason)
	for i, line := range guidance.remedy {
		label := "remedy:"
		if i > 0 {
			label = "       "
		}
		fmt.Fprintf(os.Stderr, "[security] %s %s\n", label, line)
	}
}

func resolveTamperDelay() time.Duration {
	return DefaultTamperDelayMs * time.Millisecond
}
