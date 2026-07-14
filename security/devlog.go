package security

import (
	"fmt"
	"os"
	"strings"
)

const (
	securityLogLevelNone  = 0
	securityLogLevelError = 1
	securityLogLevelInfo  = 2
	securityLogLevelDebug = 3
	securityLogLevelTrace = 4
)

var securityDevMode bool
var securityLogLevel = securityLogLevelNone

func SetSecurityDevMode(enabled bool) {
	securityDevMode = enabled
}

func SetSecurityLogLevel(level string) {
	raw := strings.TrimSpace(strings.ToLower(level))
	switch raw {
	case "error", "err":
		securityLogLevel = securityLogLevelError
	case "info":
		securityLogLevel = securityLogLevelInfo
	case "debug":
		securityLogLevel = securityLogLevelDebug
	case "trace":
		securityLogLevel = securityLogLevelTrace
	default:
		securityLogLevel = securityLogLevelNone
	}
}

func securityDevModeEnabled() bool {
	return securityDevMode
}

func resolveSecurityLogLevel() int {
	return securityLogLevel
}

func securityDevLogEnabled() bool {
	if !securityDevModeEnabled() {
		return false
	}
	return resolveSecurityLogLevel() >= securityLogLevelDebug
}

func securityDevLogf(format string, args ...any) {
	if !securityDevLogEnabled() {
		return
	}
	fmt.Fprintf(os.Stderr, "[security-dev] "+format+"\n", args...)
}
