package builtin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestLuaRunStringSuccess(t *testing.T) {
	result := LuaRunString(&object.String{Value: "return 'mutant-lua'"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}

	resObj, _ := hashValueByKey(hash, "result").(*object.String)
	if resObj == nil || resObj.Value != "mutant-lua" {
		t.Fatalf("unexpected result: %+v", resObj)
	}
}

// TestLuaSandboxBlocksHostAccess verifies the "safe" loader does not expose the
// host: io must be absent and the dangerous os.* calls must be stripped, while
// safe os time helpers remain available.
func TestLuaSandboxBlocksHostAccess(t *testing.T) {
	luaResult := func(t *testing.T, code string) string {
		t.Helper()
		payload, errObj := unwrapPair(t, LuaRunString(&object.String{Value: code}))
		if errObj != nil {
			t.Fatalf("unexpected error: %s", errObj.Inspect())
		}
		hash, ok := payload.(*object.Hash)
		if !ok {
			t.Fatalf("expected HASH result, got=%T", payload)
		}
		if okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean); okObj == nil || !okObj.Value {
			t.Fatalf("expected ok=true for %q", code)
		}
		resObj, _ := hashValueByKey(hash, "result").(*object.String)
		if resObj == nil {
			t.Fatalf("expected string result for %q", code)
		}
		return resObj.Value
	}

	blocked := map[string]string{
		"io library removed":  "return type(io)",
		"os.execute stripped": "return type(os.execute)",
		"os.exit stripped":    "return type(os.exit)",
		"os.remove stripped":  "return type(os.remove)",
		"os.getenv stripped":  "return type(os.getenv)",
		"load removed":        "return type(load)",
		"dofile removed":      "return type(dofile)",
	}
	for name, code := range blocked {
		t.Run(name, func(t *testing.T) {
			if got := luaResult(t, code); got != "nil" {
				t.Fatalf("expected %q to be nil (blocked), got=%q", code, got)
			}
		})
	}

	// Safe os time helpers must still work.
	if got := luaResult(t, "return type(os.time)"); got != "function" {
		t.Fatalf("expected os.time to remain a function, got=%q", got)
	}
}

func TestLuaRunStringCapturesPrintOutputWithoutReturn(t *testing.T) {
	result := LuaRunString(&object.String{Value: "print('hello'); print('world')"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}

	resObj, _ := hashValueByKey(hash, "result").(*object.String)
	if resObj == nil || resObj.Value != "hello\nworld" {
		t.Fatalf("unexpected print capture result: %+v", resObj)
	}
}

func TestLuaRunStringNilReturnUsesExplicitNilString(t *testing.T) {
	result := LuaRunString(&object.String{Value: "return nil"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}

	resObj, _ := hashValueByKey(hash, "result").(*object.String)
	if resObj == nil || resObj.Value != "nil" {
		t.Fatalf("expected result=nil, got=%+v", resObj)
	}
}

func TestLuaRunStringMutantReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("from-mutant-read-file"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	code := "local d,e = mutant.read_file('" + filepath.ToSlash(path) + "'); if not d then return 'ERR:' .. tostring(e) end; return d"
	result := LuaRunString(&object.String{Value: code})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}

	resObj, _ := hashValueByKey(hash, "result").(*object.String)
	if resObj == nil || resObj.Value != "from-mutant-read-file" {
		t.Fatalf("unexpected result: %+v", resObj)
	}
}

func TestLuaRunFileSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "patch.lua")
	if err := os.WriteFile(path, []byte("return 'file-lua'"), 0644); err != nil {
		t.Fatalf("failed to write temp lua file: %v", err)
	}

	result := LuaRunFile(&object.String{Value: path})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}
}

func TestLuaRunHTTPCodeSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("return 'http-lua'"))
	}))
	defer server.Close()

	result := LuaRunHTTP(&object.String{Value: server.URL})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || !okObj.Value {
		t.Fatalf("expected ok=true")
	}

	resObj, _ := hashValueByKey(hash, "result").(*object.String)
	if resObj == nil || resObj.Value != "http-lua" {
		t.Fatalf("unexpected result: %+v", resObj)
	}
}

func TestLuaRunFileBlockedWithoutCapability(t *testing.T) {
	result := LuaRunFile(&object.String{Value: "patch.lua"})
	_, errObj := unwrapPair(t, result)
	if errObj == nil {
		t.Fatalf("expected non-nil pair error")
	}
}

func TestLuaRunHTTPBlockedWithoutCapability(t *testing.T) {
	result := LuaRunHTTP(&object.String{Value: "https://example.com"})
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected pair error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	okObj, _ := hashValueByKey(hash, "ok").(*object.Boolean)
	if okObj == nil || okObj.Value {
		t.Fatalf("expected ok=false")
	}

	errMsgObj, _ := hashValueByKey(hash, "error").(*object.String)
	if errMsgObj == nil || errMsgObj.Value == "" {
		t.Fatalf("expected non-empty error")
	}
}
