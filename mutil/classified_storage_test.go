package mutil

import (
	"testing"

	"mutant/object"
)

// Every variable the VM holds is stored through EncryptObject and read back
// through DecryptObject, so a mark this round trip drops is a mark no sink
// ever sees. That was the case until the mark rode beside the ciphertext.
func TestStorageKeepsTheClassifiedMark(t *testing.T) {
	mark := &object.Classification{RecordUID: "rec", Tags: []string{"t"}, Labels: []string{"pii"}}
	for name, value := range map[string][]byte{"a buffer": []byte("secret"), "an empty buffer": {}} {
		stored, err := EncryptObject(&object.Bytes{Value: append([]byte(nil), value...), Classified: mark}, 1024, "pw")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		loaded, err := DecryptObject(stored, 1024, "pw")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, ok := loaded.(*object.Bytes)
		if !ok || string(b.Value) != string(value) {
			t.Fatalf("%s came back as %#v", name, loaded)
		}
		if b.Classified != mark {
			t.Fatalf("%s lost its mark in storage", name)
		}
	}

	stored, _ := EncryptObject(&object.Bytes{Value: []byte("plain")}, 1024, "pw")
	loaded, _ := DecryptObject(stored, 1024, "pw")
	if loaded.(*object.Bytes).Classified != nil {
		t.Fatal("an unmarked buffer came back marked")
	}
}
