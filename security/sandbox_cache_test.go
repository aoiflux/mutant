package security

import "testing"

// Sandbox detection is expensive -- on Windows it spawns tasklist, three wmic
// queries, powershell and four reg queries, about a second in total -- and the
// VM calls it from its instruction stream, because OpChkSnd runs IsSandboxed()
// wherever the compiler injected a check. Uncached, a program's runtime grew by
// roughly a second for every injected check it reached: a 200-function program
// that only declared its functions and printed one line took 103 seconds.
//
// These tests pin the cache rather than the timing, so they mean the same thing
// on a platform whose detector is a stub.

// A sentinel planted in the cache must survive the next call. Only a genuine
// cache hit can return it; a second detection would overwrite it with whatever
// this machine actually looks like.
func TestSandboxDetectionIsCachedForTheProcess(t *testing.T) {
	t.Cleanup(resetSandboxCache)
	resetSandboxCache()

	if _, _, err := DetectSandboxType(); err != nil {
		t.Fatalf("first detection failed: %s", err)
	}

	sandboxCached = sandboxDetection{
		Type:       "sentinel-hypervisor",
		Confidence: sandboxDetectedThreshold + 1,
		Indicators: []string{"sentinel:indicator"},
	}
	sandboxCachedErr = nil

	typ, confidence, err := DetectSandboxType()
	if err != nil {
		t.Fatalf("cached detection returned an error: %s", err)
	}
	if typ != "sentinel-hypervisor" {
		t.Fatalf("detection ran again: got type %q, want the cached sentinel", typ)
	}
	if confidence != sandboxDetectedThreshold+1 {
		t.Fatalf("detection ran again: got confidence %d, want %d", confidence, sandboxDetectedThreshold+1)
	}

	if !IsSandboxed() {
		t.Fatal("IsSandboxed disagreed with the cached confidence")
	}

	indicators, err := GetSandboxIndicators()
	if err != nil {
		t.Fatalf("cached indicators returned an error: %s", err)
	}
	if len(indicators) != 1 || indicators[0] != "sentinel:indicator" {
		t.Fatalf("detection ran again: got indicators %v", indicators)
	}
}

// GetSandboxIndicators hands out a copy. A caller that edits what it got must
// not be able to rewrite what every later caller sees.
func TestSandboxIndicatorsAreCopiedOutOfTheCache(t *testing.T) {
	t.Cleanup(resetSandboxCache)
	resetSandboxCache()

	if _, _, err := DetectSandboxType(); err != nil {
		t.Fatalf("first detection failed: %s", err)
	}
	sandboxCached = sandboxDetection{
		Type:       "sentinel-hypervisor",
		Confidence: sandboxDetectedThreshold + 1,
		Indicators: []string{"sentinel:indicator"},
	}

	first, err := GetSandboxIndicators()
	if err != nil {
		t.Fatalf("reading indicators failed: %s", err)
	}
	first[0] = "tampered"

	second, err := GetSandboxIndicators()
	if err != nil {
		t.Fatalf("re-reading indicators failed: %s", err)
	}
	if second[0] != "sentinel:indicator" {
		t.Fatalf("a caller edited the cache through its own copy: got %q", second[0])
	}
}

// resetSandboxCache has to actually clear, or a test that changes the
// environment it is detecting would silently keep reading a stale answer.
func TestResetSandboxCacheForcesRedetection(t *testing.T) {
	t.Cleanup(resetSandboxCache)
	resetSandboxCache()

	if _, _, err := DetectSandboxType(); err != nil {
		t.Fatalf("first detection failed: %s", err)
	}
	sandboxCached = sandboxDetection{Type: "sentinel-hypervisor", Confidence: 99}

	resetSandboxCache()

	typ, _, err := DetectSandboxType()
	if err != nil {
		t.Fatalf("detection after reset failed: %s", err)
	}
	if typ == "sentinel-hypervisor" {
		t.Fatal("reset did not clear the cache")
	}
}
