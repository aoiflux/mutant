package security

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	// Deprecated compatibility constants: env overrides are no longer used.
	TamperResponseEnv = "MUTANT_TAMPER_RESPONSE"
	TamperDelayMsEnv  = "MUTANT_TAMPER_DELAY_MS"

	TamperResponseWarn      = "warn"
	TamperResponseDelay     = "delay"
	TamperResponseTerminate = "terminate"

	DefaultTamperDelayMs = 250
	MinTamperDelayMs     = 0
	MaxTamperDelayMs     = 5000
)

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
		if baseErr != nil {
			return baseErr
		}
		return errors.New("security policy violation")
	}
}

func resolveTamperDelay() time.Duration {
	return DefaultTamperDelayMs * time.Millisecond
}
