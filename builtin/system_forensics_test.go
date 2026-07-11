package builtin

import (
	"os"
	"runtime"
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

func TestProcessOpenFilesThreadsModulesAndMemoryScan(t *testing.T) {
	if runtime.GOOS == "linux" {
		ofPayload, errObj := unwrapPair(t, ProcessOpenFiles())
		if errObj != nil {
			t.Fatalf("process_open_files error: %s", errObj.Inspect())
		}
		if _, ok := ofPayload.(*object.Array); !ok {
			t.Fatalf("process_open_files payload type: %T", ofPayload)
		}

		thPayload, errObj := unwrapPair(t, ProcessThreads())
		if errObj != nil {
			t.Fatalf("process_threads error: %s", errObj.Inspect())
		}
		if _, ok := thPayload.(*object.Array); !ok {
			t.Fatalf("process_threads payload type: %T", thPayload)
		}

		modPayload, errObj := unwrapPair(t, ProcessModules())
		if errObj != nil {
			t.Fatalf("process_modules error: %s", errObj.Inspect())
		}
		if _, ok := modPayload.(*object.Array); !ok {
			t.Fatalf("process_modules payload type: %T", modPayload)
		}

		scanPayload, errObj := unwrapPair(t, ProcessMemoryScan(&object.Integer{Value: int64(os.Getpid())}, stringObj("needle")))
		if errObj != nil {
			t.Fatalf("process_memory_scan error: %s", errObj.Inspect())
		}
		scanHash, ok := scanPayload.(*object.Hash)
		if !ok {
			t.Fatalf("process_memory_scan payload type: %T", scanPayload)
		}
		if sfMustHashString(t, scanHash, "status") != "not_implemented" {
			t.Fatalf("unexpected process_memory_scan status")
		}
		return
	}

	if _, errObj := unwrapPair(t, ProcessOpenFiles()); errObj == nil {
		t.Fatalf("expected process_open_files unsupported error on %s", runtime.GOOS)
	}
	if _, errObj := unwrapPair(t, ProcessThreads()); errObj == nil {
		t.Fatalf("expected process_threads unsupported error on %s", runtime.GOOS)
	}
	if _, errObj := unwrapPair(t, ProcessModules()); errObj == nil {
		t.Fatalf("expected process_modules unsupported error on %s", runtime.GOOS)
	}
	if _, errObj := unwrapPair(t, ProcessMemoryScan(&object.Integer{Value: int64(os.Getpid())}, stringObj("needle"))); errObj == nil {
		t.Fatalf("expected process_memory_scan unsupported error on %s", runtime.GOOS)
	}
}

func TestProcessKillRefusesSelf(t *testing.T) {
	_, errObj := unwrapPair(t, ProcessKill(&object.Integer{Value: int64(os.Getpid())}))
	if errObj == nil {
		t.Fatalf("expected process_kill to refuse current process")
	}
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
