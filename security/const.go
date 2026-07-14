package security

import "errors"

// Header and footer constant strings for file identification
const (
	HEADER                      = "MUT"
	FOOTER                      = "ANT"
	StandaloneTailMarker        = "MUTANTBC"
	StandaloneTailV1            = byte(1)
	StandaloneTailV2            = byte(2)
	StandaloneTailV3            = byte(3)
	StandaloneTailV1Size        = len(StandaloneTailMarker) + 1 + 8 + 32
	StandaloneTailV2Size        = len(StandaloneTailMarker) + 1 + 8 + 32 + 8
	StandaloneTailV3Size        = len(StandaloneTailMarker) + 1 + 8 + 32 + 8 + 1 + 32
	StandaloneTailSize          = StandaloneTailV3Size
	ENCSIG                      = "MUTANT"
	SEPERATOR                   = "|"
	OUTER_SEPERATOR             = "|-|"
	TrustedPublicKeyEnv         = "MUTANT_TRUSTED_PUBLIC_KEY_HEX"
	SigningPrivateKeyEnv        = "MUTANT_SIGNING_PRIVATE_KEY_HEX"
	LocalKeyStoreDirEnv         = "MUTANT_KEYSTORE_DIR"
	ProcessProtectionEnabledEnv = "MUTANT_ENABLE_PROCESS_PROTECTION"

	LocalSigningPrivateKeyFileName = "ed25519_private_key.hex"
	LocalSigningPublicKeyFileName  = "ed25519_public_key.hex"

	DOCKER = "Docker"
)

// Linux sandbox detection files
const (
	LNX_DCKR_ENV_0 = "/.dockerenv"
	LNX_DCKR_ENV_1 = "linux:file:/.dockerenv"
)

// Error definitions
var (
	// ErrWrongSignature error is returned if signature doesn't match
	ErrWrongSignature = errors.New("wrong signature, compromised or wrong file")

	// ErrPasswordRequired error is returned when password is needed but not provided
	ErrPasswordRequired = errors.New("password required for decryption")

	// ErrInvalidMetadata error is returned when encryption metadata is malformed
	ErrInvalidMetadata = errors.New("invalid encryption metadata")

	// ErrDebuggerDetected error is returned when a debugger is detected
	ErrDebuggerDetected = errors.New("debugger detected, execution halted for security")

	// ErrSandboxDetected error is returned when a sandbox/container/vm is detected
	ErrSandboxDetected = errors.New("sandbox detected, execution halted for security")

	// ErrProcessProtectionDetected error is returned when process injection/hook activity is detected.
	ErrProcessProtectionDetected = errors.New("process protection triggered, possible injection/hook detected")

	// ErrUntrustedSigner error is returned when signed payload key does not match trusted key
	ErrUntrustedSigner = errors.New("untrusted signer public key")
)
