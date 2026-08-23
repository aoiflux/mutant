package webrepl

import (
	"sort"
	"strings"

	"mutant/builtin"
)

// Which builtins the browser REPL exposes is DERIVED from builtin/metadata.go
// rather than hand-listed. A hand-maintained allowlist goes stale the moment
// someone adds a builtin: it silently omits browser-safe ones (the previous
// list carried ~90 of 399, leaving most of the pure-computation library
// unreachable) and nothing fails when it drifts.
//
// The rule is: a builtin is browser-safe unless it needs the host. That is
// decided by two signals plus a short explicit list.

// hostCategories are capability categories that exist to touch the host — its
// filesystem, processes, memory, registry, network, or shell. None of them can
// work inside a browser sandbox.
//
// "concurrency" is here for a different reason, and it is worth stating: a wasm
// build runs on one thread, so a receive with no sender is not a slow call but a
// fatal "all goroutines are asleep" that takes the whole REPL down rather than
// returning an error the session can recover from. pmap and peach stay available
// because they always finish — they never wait on something the script has to
// arrange — which is the same line sleep_ms is already on.
var hostCategories = map[string]bool{
	"concurrency":          true,
	"binary analysis":      true,
	"browser artifacts":    true,
	"command execution":    true,
	"detection":            true,
	"disk image forensics": true,
	"filesystem":           true,
	"filesystem forensics": true,
	"hash-set forensics":   true,
	"http":                 true,
	"memory forensics":     true,
	"network":              true,
	"process forensics":    true,
	"registry forensics":   true,
	"unix artifacts":       true,
	"windows artifacts":    true,
}

// explicitDeny covers host-bound builtins that neither signal catches.
var explicitDeny = map[string]bool{
	// Reads a line from stdin; a browser session has none.
	"gets": true,
	// Fetches over the network from inside the Lua sandbox.
	"lua_run_http": true,
	// Blocks the goroutine, which under js/wasm stalls the single browser
	// thread and freezes the page.
	"sleep_ms": true,
	// Only meaningful inside a net_serve handler, which cannot exist here.
	"serve_arg":  true,
	"serve_conn": true,
	// Report host telemetry -- debugger presence, sandbox indicators, runtime
	// posture. Inside a browser they would answer confidently about a machine
	// they cannot see, which is worse than being unavailable.
	"debug_status":         true,
	"sandbox_status":       true,
	"security_diagnostics": true,
}

// takesHostPath reports whether a builtin declares a parameter that names a
// filesystem path. This catches host-bound builtins sitting in otherwise-safe
// categories -- plist_parse and bodyfile_parse read files, imphash takes a
// pe_path, db_open_disk and lua_run_file open one -- so a new builtin that
// takes a path is excluded automatically instead of leaking into the browser.
func takesHostPath(name string) (string, bool) {
	specs, ok := builtin.ParamSpecs(name)
	if !ok {
		return "", false
	}

	for _, param := range specs {
		// Optional parameters are documented with a trailing "?".
		n := strings.TrimSuffix(strings.ToLower(param.Name), "?")

		// Match whole names and explicit path-ish suffixes rather than bare
		// substrings: "direction" (db_bfs) contains "dir" but is a traversal
		// direction, not a directory.
		if n == "path" || n == "paths" || n == "dir" || n == "file" ||
			strings.HasSuffix(n, "path") || strings.Contains(n, "_path") ||
			strings.Contains(n, "file") {
			return param.Name, true
		}
	}
	return "", false
}

// BrowserSafe reports whether a builtin may be exposed to the browser REPL.
func BrowserSafe(name string) bool {
	if hostCategories[builtin.CapabilityCategory(name)] || explicitDeny[name] {
		return false
	}
	_, needsHost := takesHostPath(name)
	return !needsHost
}

// SupportedBuiltinNames returns the browser-safe builtin names, sorted.
func SupportedBuiltinNames() []string {
	names := make([]string, 0, len(builtin.Builtins))
	for _, b := range builtin.Builtins {
		if BrowserSafe(b.Name) {
			names = append(names, b.Name)
		}
	}
	sort.Strings(names)
	return names
}

func supportedBuiltinSet() map[string]struct{} {
	set := make(map[string]struct{})
	for _, b := range builtin.Builtins {
		if BrowserSafe(b.Name) {
			set[b.Name] = struct{}{}
		}
	}
	return set
}
