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

	configured := strings.ToLower(strings.TrimSpace(os.Getenv(TamperResponseEnv)))
	switch configured {
	case TamperResponseWarn, TamperResponseDelay, TamperResponseTerminate:
		return configured
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
	raw := strings.TrimSpace(os.Getenv(TamperDelayMsEnv))
	if raw == "" {
		return DefaultTamperDelayMs * time.Millisecond
	}

	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < MinTamperDelayMs || parsed > MaxTamperDelayMs {
		return DefaultTamperDelayMs * time.Millisecond
	}

	return time.Duration(parsed) * time.Millisecond
}
