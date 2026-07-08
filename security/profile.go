package security

import (
	"crypto/sha256"
	"os"
	"strings"
)

const ProtectionProfileEnv = "MUTANT_PROTECTION_PROFILE"

const (
	ProtectionProfileMinimal  = "minimal"
	ProtectionProfileStandard = "standard"
	ProtectionProfileParanoid = "paranoid"
	defaultProtectionProfile  = ProtectionProfileStandard

	ProtectionProfileMinimalCode  byte = 1
	ProtectionProfileStandardCode byte = 2
	ProtectionProfileParanoidCode byte = 3
)

func ResolveProtectionProfile() string {
	configured := strings.ToLower(strings.TrimSpace(os.Getenv(ProtectionProfileEnv)))
	switch configured {
	case ProtectionProfileMinimal, ProtectionProfileStandard, ProtectionProfileParanoid:
		return configured
	default:
		return defaultProtectionProfile
	}
}

func ResolveProtectionProfileCode() byte {
	switch ResolveProtectionProfile() {
	case ProtectionProfileMinimal:
		return ProtectionProfileMinimalCode
	case ProtectionProfileStandard:
		return ProtectionProfileStandardCode
	case ProtectionProfileParanoid:
		return ProtectionProfileParanoidCode
	default:
		return ProtectionProfileStandardCode
	}
}

func ProtectionProfileFromCode(code byte) (string, bool) {
	switch code {
	case ProtectionProfileMinimalCode:
		return ProtectionProfileMinimal, true
	case ProtectionProfileStandardCode:
		return ProtectionProfileStandard, true
	case ProtectionProfileParanoidCode:
		return ProtectionProfileParanoid, true
	default:
		return "", false
	}
}

func defaultTamperResponseForProfile(secureMode bool) string {
	switch ResolveProtectionProfile() {
	case ProtectionProfileMinimal:
		return TamperResponseWarn
	case ProtectionProfileParanoid:
		return TamperResponseTerminate
	default:
		if secureMode {
			return TamperResponseTerminate
		}
		return TamperResponseWarn
	}
}

func DefaultBuiltinCapabilityPolicy() map[string]struct{} {
	if ResolveProtectionProfile() == ProtectionProfileMinimal {
		return map[string]struct{}{"all": {}}
	}

	return map[string]struct{}{}
}

func DeriveStandaloneProvenance(payload []byte, checksum []byte, profileCode byte) [32]byte {
	seed := make([]byte, 0, len(payload)+len(checksum)+1)
	seed = append(seed, payload...)
	seed = append(seed, checksum...)
	seed = append(seed, profileCode)
	return sha256.Sum256(seed)
}
