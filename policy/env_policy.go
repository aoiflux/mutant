// Package policy holds the machine-checked statement of Mutant's configuration
// policy: Mutant takes no configuration from environment variables.
//
// The policy is enforced by TestNoMutantEnvironmentVariableNames and
// TestNoEnvironmentAccessOutsideAllowlist in this package, which run as part of
// the ordinary `go test ./...`. The prose version, with the reasoning, is in
// docs/CONFIGURATION_POLICY.md.
package policy

// EnvAccessException records a place where reading or writing the process
// environment is legitimate, and why.
//
// Mutant takes no configuration from the environment. The only permitted
// accesses are ones where the value is observed rather than obeyed -- sandbox
// and debugger detection, the process_env forensic builtin -- plus writing
// GOOS/GOARCH/CGO_ENABLED for a build-time child `go build`, which the Go
// toolchain accepts no other way.
//
// Anything not listed here fails TestNoEnvironmentAccessOutsideAllowlist.
type EnvAccessException struct {
	// File is the repository-relative path, with forward slashes.
	File string
	// Func is the enclosing top-level function or method.
	Func string
	// Lines is the exact number of source lines in Func that may touch the
	// environment. Pinning the count means a new access added inside an
	// already-allowlisted function still fails the guard.
	Lines int
	// Category is one of "detection", "evidence" or "toolchain".
	Category string
	// Why explains what makes this access something other than configuration.
	Why string
}

// EnvAccessAllowlist is the complete set of permitted environment accesses.
//
// Adding an entry is a policy decision, not a formality: it must be a value
// Mutant observes or reports rather than obeys, or a build-time `go build`
// invocation. If a Mutant user could set the variable to change what Mutant
// does, the answer is a CLI flag instead.
var EnvAccessAllowlist = []EnvAccessException{
	// detection -- Mutant observing where it is running. This is core Mutant
	// infrastructure, not configuration: the variables are set by Sandboxie, WSL,
	// a debugger or an injected library, never by a Mutant user, and the only
	// outcome they can produce is a refusal to run.
	{
		File: "security/sandbox_helpers.go", Func: "envSet", Lines: 1,
		Category: "detection",
		Why:      "The single choke point every sandbox environment probe funnels through.",
	},
	{
		File: "security/sandbox_windows.go", Func: "detectSandboxWindows", Lines: 3,
		Category: "detection",
		Why:      "Windows sandbox indicators, plus USERNAME/USERPROFILE for the Defender Application Guard account.",
	},
	{
		File: "security/antidebug_linux.go", Func: "hasDebuggerEnvironmentMarkers", Lines: 2,
		Category: "detection",
		Why:      "LD_PRELOAD and Linux debugger markers, read as indicators of compromise.",
	},
	{
		File: "security/antidebug_darwin.go", Func: "hasDebuggerEnvironmentMarkersDarwin", Lines: 2,
		Category: "detection",
		Why:      "DYLD_INSERT_LIBRARIES and macOS debugger markers, read as indicators of compromise.",
	},
	{
		File: "security/antitamper_detectors.go", Func: "detectFridaPtrace", Lines: 1,
		Category: "detection",
		Why:      "Frida instrumentation markers left in the environment by the injector.",
	},
	{
		File: "security/antitamper_windows.go", Func: "findInjectionEnvMarkers", Lines: 1,
		Category: "detection",
		Why:      "Windows library-injection indicators, reported as probe detail.",
	},

	// evidence -- Mutant reporting on a subject process. The value is output, not
	// input: nothing branches on it.
	{
		File: "builtin/system_forensics.go", Func: "ProcessEnv", Lines: 2,
		Category: "evidence",
		Why:      "Backs the process_env builtin, which returns a subject process's environment as forensic output.",
	},

	// toolchain -- build-time `go build`. GOOS, GOARCH and CGO_ENABLED have no
	// command-line equivalent; the Go toolchain reads them from the child
	// environment or not at all.
	{
		File: "generator/release_assets.go", Func: "buildReleaseRuntimeBinary", Lines: 1,
		Category: "toolchain",
		Why:      "Cross-target release builds pass GOOS/GOARCH/CGO_ENABLED to a child go build.",
	},
	{
		File: "cmd/wasmreplserve/main.go", Func: "ensureWasmBinary", Lines: 1,
		Category: "toolchain",
		Why:      "The WASM REPL builder passes GOOS=js/GOARCH=wasm to a child go build.",
	},
	{
		File: "builtin/fingerprint_builtins_test.go", Func: "TestImphashOnWindowsPE", Lines: 1,
		Category: "toolchain",
		Why:      "Cross-compiles a throwaway Windows PE to fingerprint; needs GOOS/GOARCH on the child build.",
	},
}
