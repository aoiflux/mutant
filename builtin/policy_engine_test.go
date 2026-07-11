package builtin

import (
	"strings"
	"testing"

	"mutant/object"
)

func TestPolicyLoadAndRules(t *testing.T) {
	result := PolicyLoad(stringObj("access_policy"), testRegoPolicyConfigObject())
	payload, errObj := unwrapPair(t, result)
	if errObj != nil {
		t.Fatalf("unexpected error: %s", errObj.Inspect())
	}

	loadedHash, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("payload is not HASH. got=%T", payload)
	}
	loadedObj := testMustHashValue(t, loadedHash, "loaded")
	loaded, ok := loadedObj.(*object.Boolean)
	if !ok || !loaded.Value {
		t.Fatalf("expected loaded=true")
	}

	rulesResult := PolicyRules(stringObj("access_policy"))
	rulesPayload, rulesErr := unwrapPair(t, rulesResult)
	if rulesErr != nil {
		t.Fatalf("unexpected error from policy_rules: %s", rulesErr.Inspect())
	}
	arr, ok := rulesPayload.(*object.Array)
	if !ok {
		t.Fatalf("policy_rules payload is not ARRAY. got=%T", rulesPayload)
	}
	if len(arr.Elements) == 0 {
		t.Fatalf("expected non-empty rules array")
	}
}

func TestPolicyEvalAndAllow(t *testing.T) {
	_, errObj := unwrapPair(t, PolicyLoad(stringObj("allow_policy"), testRegoPolicyConfigObject()))
	if errObj != nil {
		t.Fatalf("unexpected load error: %s", errObj.Inspect())
	}

	facts := makeHashObject(map[string]object.Object{
		"path": stringObj("/safe/bin"),
		"user": stringObj("analyst"),
	})

	evalResult := PolicyEval(stringObj("allow_policy"), facts)
	evalPayload, evalErr := unwrapPair(t, evalResult)
	if evalErr != nil {
		t.Fatalf("unexpected eval error: %s", evalErr.Inspect())
	}

	evalHash, ok := evalPayload.(*object.Hash)
	if !ok {
		t.Fatalf("policy_eval payload is not HASH. got=%T", evalPayload)
	}

	allowObj := testMustHashValue(t, evalHash, "allow")
	allow, ok := allowObj.(*object.Boolean)
	if !ok || !allow.Value {
		t.Fatalf("expected allow=true")
	}

	decisionObj := testMustHashValue(t, evalHash, "decision")
	decision, ok := decisionObj.(*object.Hash)
	if !ok {
		t.Fatalf("decision is not HASH. got=%T", decisionObj)
	}
	pathObj := testMustHashValue(t, decision, "path")
	pathStr, ok := pathObj.(*object.String)
	if !ok || pathStr.Value != "/safe/bin" {
		t.Fatalf("unexpected decision.path value")
	}

	allowResult := PolicyAllow(stringObj("allow_policy"), facts)
	allowPayload, allowErr := unwrapPair(t, allowResult)
	if allowErr != nil {
		t.Fatalf("unexpected allow error: %s", allowErr.Inspect())
	}
	allowBool, ok := allowPayload.(*object.Boolean)
	if !ok || !allowBool.Value {
		t.Fatalf("expected policy_allow to return true")
	}
}

func TestPolicyTrace(t *testing.T) {
	_, errObj := unwrapPair(t, PolicyLoad(stringObj("trace_policy"), testRegoPolicyConfigObject()))
	if errObj != nil {
		t.Fatalf("unexpected load error: %s", errObj.Inspect())
	}

	facts := makeHashObject(map[string]object.Object{
		"path": stringObj("/tmp/malware"),
		"user": stringObj("guest"),
	})

	traceResult := PolicyTrace(stringObj("trace_policy"), facts)
	tracePayload, traceErr := unwrapPair(t, traceResult)
	if traceErr != nil {
		t.Fatalf("unexpected trace error: %s", traceErr.Inspect())
	}

	traceArr, ok := tracePayload.(*object.Array)
	if !ok {
		t.Fatalf("trace payload is not ARRAY. got=%T", tracePayload)
	}
	if len(traceArr.Elements) == 0 {
		t.Fatalf("expected non-empty trace")
	}
}

func TestPolicyBuiltinsErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "policy_load bad name type",
			call: func() object.Object { return PolicyLoad(intObj(1), testRegoPolicyConfigObject()) },
		},
		{
			name: "policy_rules unknown policy",
			call: func() object.Object { return PolicyRules(stringObj("does-not-exist")) },
		},
		{
			name: "policy_eval facts type error",
			call: func() object.Object { return PolicyEval(testRegoPolicyConfigObject(), stringObj("not-hash")) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.call()
			_, errObj := unwrapPair(t, result)
			if errObj == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.name == "policy_rules unknown policy" && !strings.Contains(errObj.Message, "not found") {
				t.Fatalf("unexpected error: %s", errObj.Message)
			}
		})
	}
}

func testRegoPolicyConfigObject() *object.Hash {
	return makeHashObject(map[string]object.Object{
		"module": stringObj(`package access

default allow = false

allow {
	startswith(input.path, "/safe")
	input.user != "guest"
}

decision = {
	"path": input.path,
	"user": input.user,
	"allow": allow,
}

rules = [
  {"id": "allow_safe_path", "description": "path must start with /safe"},
  {"id": "deny_guest_user", "description": "guest user denied"},
]`),
		"eval_query":  stringObj("data.access.decision"),
		"allow_query": stringObj("data.access.allow"),
		"rules_query": stringObj("data.access.rules"),
	})
}

func testMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}
