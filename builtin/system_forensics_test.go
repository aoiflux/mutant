package builtin

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"mutant/object"
)

func TestProcessListAndTree(t *testing.T) {
	listPayload, errObj := unwrapPair(t, ProcessList())
	if errObj != nil {
		t.Fatalf("process_list error: %s", errObj.Inspect())
	}
	listArr, ok := listPayload.(*object.Array)
	if !ok {
		t.Fatalf("process_list payload type: %T", listPayload)
	}
	if len(listArr.Elements) == 0 {
		t.Fatalf("process_list returned empty process set")
	}

	treePayload, errObj := unwrapPair(t, ProcessTree())
	if errObj != nil {
		t.Fatalf("process_tree error: %s", errObj.Inspect())
	}
	if _, ok := treePayload.(*object.Hash); !ok {
		t.Fatalf("process_tree payload type: %T", treePayload)
	}
}

func TestProcessEnvAndHash(t *testing.T) {
	envPayload, errObj := unwrapPair(t, ProcessEnv())
	if errObj != nil {
		t.Fatalf("process_env error: %s", errObj.Inspect())
	}
	envHash, ok := envPayload.(*object.Hash)
	if !ok {
		t.Fatalf("process_env payload type: %T", envPayload)
	}
	if len(envHash.Pairs) == 0 {
		t.Fatalf("process_env returned empty environment")
	}

	hashPayload, errObj := unwrapPair(t, ProcessHash())
	if errObj != nil {
		t.Fatalf("process_hash error: %s", errObj.Inspect())
	}
	hashObj, ok := hashPayload.(*object.Hash)
	if !ok {
		t.Fatalf("process_hash payload type: %T", hashPayload)
	}
	sha := sfMustHashString(t, hashObj, "sha256")
	if len(sha) != 64 {
		t.Fatalf("unexpected sha256 length: %d", len(sha))
	}
}

func TestProcessOpenFilesThreadsModules(t *testing.T) {
	// open files (self): cross-platform via gopsutil. Tolerate a privilege/lookup
	// error, but it must never be a blanket "unsupported OS" gate.
	ofPayload, errObj := unwrapPair(t, ProcessOpenFiles())
	if errObj == nil {
		if _, ok := ofPayload.(*object.Array); !ok {
			t.Fatalf("process_open_files payload type: %T", ofPayload)
		}
	} else {
		t.Logf("process_open_files error on %s (tolerated): %s", runtime.GOOS, errObj.Message)
	}

	// threads (self): the count is available on every supported OS; the tids
	// array is populated where the platform exposes them.
	thPayload, errObj := unwrapPair(t, ProcessThreads())
	if errObj != nil {
		t.Fatalf("process_threads error: %s", errObj.Inspect())
	}
	thHash, ok := thPayload.(*object.Hash)
	if !ok {
		t.Fatalf("process_threads payload type: %T", thPayload)
	}
	if got := sfHashInt(t, thHash, "count"); got < 1 {
		t.Fatalf("expected at least one thread, got %d", got)
	}
	if _, ok := sfHashValue(t, thHash, "tids").(*object.Array); !ok {
		t.Fatalf("process_threads tids must be an ARRAY")
	}

	// modules (self): a real module list on Linux (memory maps) and Windows
	// (Toolhelp32); an honest error on platforms without a backend (never a fake
	// empty success).
	modPayload, errObj := unwrapPair(t, ProcessModules())
	switch {
	case runtime.GOOS == "linux" || runtime.GOOS == "windows":
		if errObj != nil {
			t.Fatalf("process_modules error on %s: %s", runtime.GOOS, errObj.Inspect())
		}
		modArr, ok := modPayload.(*object.Array)
		if !ok {
			t.Fatalf("process_modules payload type: %T", modPayload)
		}
		if len(modArr.Elements) == 0 {
			t.Fatalf("process_modules returned no modules for self on %s", runtime.GOOS)
		}
	case errObj == nil:
		if _, ok := modPayload.(*object.Array); !ok {
			t.Fatalf("process_modules payload type: %T", modPayload)
		}
	default:
		if !strings.Contains(errObj.Message, "not available") {
			t.Fatalf("unexpected process_modules error on %s: %s", runtime.GOOS, errObj.Message)
		}
	}
}

func TestProcessMemoryScanReal(t *testing.T) {
	// A distinctive pattern kept alive in this process's memory must be found by a
	// real self-scan on supported platforms (Linux, Windows).
	needle := []byte("mutant-memscan-marker-\x00\x01\x02-a7f3")
	keepAlive := make([]byte, len(needle))
	copy(keepAlive, needle)

	payload, errObj := unwrapPair(t, ProcessMemoryScan(&object.Integer{Value: int64(os.Getpid())}, stringObj(string(needle))))

	switch runtime.GOOS {
	case "linux", "windows":
		if errObj != nil {
			t.Fatalf("process_memory_scan error on %s: %s", runtime.GOOS, errObj.Inspect())
		}
		h, ok := payload.(*object.Hash)
		if !ok {
			t.Fatalf("process_memory_scan payload type: %T", payload)
		}
		if got := sfHashInt(t, h, "matched"); got < 1 {
			t.Fatalf("expected the marker to be found in self memory, matched=%d", got)
		}
		addrs, ok := sfHashValue(t, h, "addresses").(*object.Array)
		if !ok || len(addrs.Elements) < 1 {
			t.Fatalf("expected at least one match address")
		}
	default:
		if errObj == nil {
			t.Fatalf("expected process_memory_scan unsupported error on %s", runtime.GOOS)
		}
	}
	runtime.KeepAlive(keepAlive)

	// Non-self pid and empty pattern are rejected honestly.
	otherPid := os.Getpid() + 1
	if _, e := unwrapPair(t, ProcessMemoryScan(&object.Integer{Value: int64(otherPid)}, stringObj("x"))); e == nil {
		t.Fatal("scanning a non-self pid should error")
	}
	if _, e := unwrapPair(t, ProcessMemoryScan(&object.Integer{Value: int64(os.Getpid())}, stringObj(""))); e == nil {
		t.Fatal("empty pattern should error")
	}
}

func TestProcessKillRefusesSelf(t *testing.T) {
	_, errObj := unwrapPair(t, ProcessKill(&object.Integer{Value: int64(os.Getpid())}))
	if errObj == nil {
		t.Fatalf("expected process_kill to refuse current process")
	}
}

func sfHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}

func sfHashInt(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	v, ok := sfHashValue(t, hash, key).(*object.Integer)
	if !ok {
		t.Fatalf("key %q is not INTEGER", key)
	}
	return v.Value
}

func sfMustHashString(t *testing.T, hash *object.Hash, key string) string {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	str, ok := pair.Value.(*object.String)
	if !ok {
		t.Fatalf("key %q is not STRING", key)
	}
	return str.Value
}
