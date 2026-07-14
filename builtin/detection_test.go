package builtin

import (
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestDetectPersistence(t *testing.T) {
	facts := makeHashObject(map[string]object.Object{
		"autorun_keys": &object.Array{Elements: []object.Object{
			stringObj(`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Bad`),
		}},
		"startup_files": &object.Array{Elements: []object.Object{
			stringObj(`C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk`),
		}},
	})

	payload, errObj := unwrapPair(t, DetectPersistence(facts))
	if errObj != nil {
		t.Fatalf("detect_persistence error: %s", errObj.Inspect())
	}
	h := dtMustHash(t, payload)
	if !dtMustHashBool(t, h, "detected") {
		t.Fatalf("expected persistence detection")
	}
}

func TestDetectInjection(t *testing.T) {
	fixture := dtWriteMemoryFixture(t)
	facts := makeHashObject(map[string]object.Object{"mem_path": stringObj(fixture)})
	payload, errObj := unwrapPair(t, DetectInjection(facts))
	if errObj != nil {
		t.Fatalf("detect_injection error: %s", errObj.Inspect())
	}
	h := dtMustHash(t, payload)
	if !dtMustHashBool(t, h, "detected") {
		t.Fatalf("expected injection detection")
	}
}

func TestDetectNetworkBeacon(t *testing.T) {
	flows := &object.Array{Elements: []object.Object{
		makeHashObject(map[string]object.Object{"dst": stringObj("c2.example")}),
		makeHashObject(map[string]object.Object{"dst": stringObj("c2.example")}),
		makeHashObject(map[string]object.Object{"dst": stringObj("c2.example")}),
	}}
	payload, errObj := unwrapPair(t, DetectNetworkBeacon(flows))
	if errObj != nil {
		t.Fatalf("detect_network_beacon error: %s", errObj.Inspect())
	}
	h := dtMustHash(t, payload)
	if !dtMustHashBool(t, h, "detected") {
		t.Fatalf("expected beacon detection")
	}
}

func TestDetectPrivEsc(t *testing.T) {
	signals := makeHashObject(map[string]object.Object{
		"token_theft":      boolObj(true),
		"uac_bypass":       boolObj(false),
		"lsass_access":     boolObj(true),
		"se_debug_enabled": boolObj(false),
	})
	payload, errObj := unwrapPair(t, DetectPrivEsc(signals))
	if errObj != nil {
		t.Fatalf("detect_priv_esc error: %s", errObj.Inspect())
	}
	h := dtMustHash(t, payload)
	if dtMustHashInt(t, h, "score") <= 0 {
		t.Fatalf("expected non-zero priv esc score")
	}
}

func TestDetectSuspiciousFiles(t *testing.T) {
	files := dtWriteFileFixtures(t)
	arr := &object.Array{Elements: []object.Object{stringObj(files[0]), stringObj(files[1])}}
	payload, errObj := unwrapPair(t, DetectSuspiciousFiles(arr))
	if errObj != nil {
		t.Fatalf("detect_suspicious_files error: %s", errObj.Inspect())
	}
	h := dtMustHash(t, payload)
	if !dtMustHashBool(t, h, "detected") {
		t.Fatalf("expected suspicious file detection")
	}
}

func TestDetectErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{name: "persistence bad type", call: func() object.Object { return DetectPersistence(intObj(1)) }},
		{name: "injection missing path", call: func() object.Object { return DetectInjection(makeHashObject(map[string]object.Object{})) }},
		{name: "beacon bad flow shape", call: func() object.Object {
			return DetectNetworkBeacon(&object.Array{Elements: []object.Object{stringObj("bad")}})
		}},
		{name: "priv esc bad type", call: func() object.Object { return DetectPrivEsc(stringObj("bad")) }},
		{name: "suspicious files bad type", call: func() object.Object { return DetectSuspiciousFiles(stringObj("bad")) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errObj := unwrapPair(t, tt.call())
			if errObj == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func dtWriteMemoryFixture(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "inject.bin")
	data := []byte{0x4d, 0x5a, 0x00, 0x00, 0x90, 0x90, 0x90, 0xfc, 0xe8, 0x4d, 0x5a}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func dtWriteFileFixtures(t *testing.T) []string {
	t.Helper()
	tmp := t.TempDir()
	plain := filepath.Join(tmp, "good.txt")
	bad := filepath.Join(tmp, "dropper.txt")
	if err := os.WriteFile(plain, []byte("harmless notes"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(bad, []byte{0x4d, 0x5a, 1, 2, 3, 4, 5, 6, 7, 8}, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return []string{bad, plain}
}

func dtMustHash(t *testing.T, obj object.Object) *object.Hash {
	t.Helper()
	h, ok := obj.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH: %T", obj)
	}
	return h
}

func dtMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return pair.Value
}

func dtMustHashBool(t *testing.T, hash *object.Hash, key string) bool {
	t.Helper()
	obj := dtMustHashValue(t, hash, key)
	b, ok := obj.(*object.Boolean)
	if !ok {
		t.Fatalf("key %s is not BOOLEAN: %T", key, obj)
	}
	return b.Value
}

func dtMustHashInt(t *testing.T, hash *object.Hash, key string) int64 {
	t.Helper()
	obj := dtMustHashValue(t, hash, key)
	i, ok := obj.(*object.Integer)
	if !ok {
		t.Fatalf("key %s is not INTEGER: %T", key, obj)
	}
	return i.Value
}
