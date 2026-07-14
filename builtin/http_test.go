package builtin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mutant/object"
)

func TestHttpRequestAcceptsStructHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("XToken"); got != "abc123" {
			t.Fatalf("unexpected header XToken=%q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	headers := &object.Struct{
		TypeName: "Headers",
		Fields: map[string]object.Object{
			"XToken": &object.String{Value: "abc123"},
		},
	}

	result := HttpRequest(
		&object.String{Value: "GET"},
		&object.String{Value: server.URL},
		&object.String{Value: ""},
		headers,
	)

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	status := hashFieldInt(t, hash, "status")
	if status != 200 {
		t.Fatalf("unexpected status: got=%d, want=200", status)
	}
}

func TestHttpPostAcceptsStructBodyAsJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("request body is not JSON: %v", err)
		}

		if payload["name"] != "mutant" {
			t.Fatalf("unexpected payload name=%v", payload["name"])
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	body := &object.Struct{
		TypeName: "Body",
		Fields: map[string]object.Object{
			"name": &object.String{Value: "mutant"},
			"age":  &object.Integer{Value: 3},
		},
	}

	result := HttpPost(
		&object.String{Value: server.URL},
		body,
		&object.String{Value: "application/json"},
	)

	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	hash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result, got=%T", payload)
	}

	status := hashFieldInt(t, hash, "status")
	if status != 201 {
		t.Fatalf("unexpected status: got=%d, want=201", status)
	}
}

func hashFieldInt(t *testing.T, h *object.Hash, key string) int64 {
	t.Helper()

	k := (&object.String{Value: key}).HashKey()
	pair, ok := h.Pairs[k]
	if !ok {
		t.Fatalf("missing key %q", key)
	}

	v, ok := pair.Value.(*object.Integer)
	if !ok {
		t.Fatalf("key %q not INTEGER, got=%T", key, pair.Value)
	}
	return v.Value
}
