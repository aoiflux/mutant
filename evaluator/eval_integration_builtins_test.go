package evaluator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"mutant/object"
)

func TestBuiltinIntegrationCacheAndGraphDB(t *testing.T) {
	input := `
	let opened = db_open();
	let handle = opened[0];
	let a1 = db_add_artifact(handle, "process", {"pid": 1337, "name": "evil.exe"});
	let a2 = db_add_artifact(handle, "file", {"path": "C:/Temp/drop.bin"});
	let rel = db_add_relation(handle, a1[0]["node_id"], a2[0]["node_id"], "writes");
	let timeline = db_timeline(handle);
	let query = db_query(handle);

	let copen = cache_open("eval_int_cache");
	let cput = cache_put("eval_int_cache", "latest_node", a2[0]["node_id"]);
	let cget = cache_get("eval_int_cache", "latest_node");

	let close = db_close(handle);

	{
		"open_err": opened[1],
		"a1_err": a1[1],
		"a2_err": a2[1],
		"rel_err": rel[1],
		"timeline_err": timeline[1],
		"query_err": query[1],
		"cache_open_err": copen[1],
		"cache_put_err": cput[1],
		"cache_get_err": cget[1],
		"close_err": close[1],
		"timeline_len": len(timeline[0]),
		"query_len": len(query[0]),
		"cached_found": cget[0]["found"],
		"cached_value": cget[0]["value"]
	}
	`

	evaluated := testEval(input)
	result, ok := evaluated.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result. got=%T", evaluated)
	}

	for _, key := range []string{
		"open_err",
		"a1_err",
		"a2_err",
		"rel_err",
		"timeline_err",
		"query_err",
		"cache_open_err",
		"cache_put_err",
		"cache_get_err",
		"close_err",
	} {
		testNullObject(t, hashValue(result, key))
	}

	timelineLen, ok := hashValue(result, "timeline_len").(*object.Integer)
	if !ok || timelineLen.Value < 3 {
		t.Fatalf("unexpected timeline_len: %v", hashValue(result, "timeline_len"))
	}

	queryLen, ok := hashValue(result, "query_len").(*object.Integer)
	if !ok || queryLen.Value < 2 {
		t.Fatalf("unexpected query_len: %v", hashValue(result, "query_len"))
	}

	found, ok := hashValue(result, "cached_found").(*object.Boolean)
	if !ok || !found.Value {
		t.Fatalf("expected cached_found=true")
	}

	switch v := hashValue(result, "cached_value").(type) {
	case *object.Integer:
		if v.Value <= 0 {
			t.Fatalf("expected positive cached node id. got=%d", v.Value)
		}
	case *object.Float:
		if v.Value <= 0 {
			t.Fatalf("expected positive cached node id. got=%f", v.Value)
		}
	default:
		t.Fatalf("cached_value has unexpected type. got=%T", v)
	}
}

func TestBuiltinIntegrationMemoryAndDetection(t *testing.T) {
	fixture := writeIntegrationMemoryFixture(t)
	fixture = filepath.ToSlash(fixture)

	input := fmt.Sprintf(`
	let pe = mem_find_pe(%q);
	let inj = detect_injection({"mem_path": %q});
	{
		"pe_err": pe[1],
		"inj_err": inj[1],
		"pe_count": len(pe[0]),
		"detected": inj[0]["detected"]
	}
	`, fixture, fixture)

	evaluated := testEval(input)
	result, ok := evaluated.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result. got=%T", evaluated)
	}

	testNullObject(t, hashValue(result, "pe_err"))
	testNullObject(t, hashValue(result, "inj_err"))

	peCount, ok := hashValue(result, "pe_count").(*object.Integer)
	if !ok || peCount.Value < 1 {
		t.Fatalf("expected pe_count >= 1")
	}

	detected, ok := hashValue(result, "detected").(*object.Boolean)
	if !ok || !detected.Value {
		t.Fatalf("expected detected=true")
	}
}

func TestBuiltinIntegrationPolicyAndCache(t *testing.T) {
	module := `package access


default allow = false

allow {
	input.ok
}
`

	input := fmt.Sprintf(`
	let loaded = policy_load("eval_policy", {
		"module": "%s",
		"eval_query": "data.access.allow",
		"allow_query": "data.access.allow",
		"rules_query": "data.access.allow"
	});

	let evald = policy_eval("eval_policy", {"ok": true});
	let allow = policy_allow("eval_policy", {"ok": true});
	let copen = cache_open("eval_policy_cache");
	let cput = cache_put("eval_policy_cache", "allow", allow[0]);
	let cget = cache_get("eval_policy_cache", "allow");

	{
		"load_err": loaded[1],
		"eval_err": evald[1],
		"allow_err": allow[1],
		"cache_open_err": copen[1],
		"cache_put_err": cput[1],
		"cache_get_err": cget[1],
		"allow_value": allow[0],
		"decision_value": evald[0]["decision"],
		"cached_found": cget[0]["found"],
		"cached_allow": cget[0]["value"]
	}
	`, module)

	evaluated := testEval(input)
	result, ok := evaluated.(*object.Hash)
	if !ok {
		t.Fatalf("expected HASH result. got=%T", evaluated)
	}

	for _, key := range []string{"load_err", "eval_err", "allow_err", "cache_open_err", "cache_put_err", "cache_get_err"} {
		testNullObject(t, hashValue(result, key))
	}

	allowValue, ok := hashValue(result, "allow_value").(*object.Boolean)
	if !ok || !allowValue.Value {
		t.Fatalf("expected allow_value=true")
	}

	decisionValue, ok := hashValue(result, "decision_value").(*object.Boolean)
	if !ok || !decisionValue.Value {
		t.Fatalf("expected decision_value=true")
	}

	cachedFound, ok := hashValue(result, "cached_found").(*object.Boolean)
	if !ok || !cachedFound.Value {
		t.Fatalf("expected cached_found=true")
	}

	cachedAllow, ok := hashValue(result, "cached_allow").(*object.Boolean)
	if !ok || !cachedAllow.Value {
		t.Fatalf("expected cached_allow=true")
	}
}

func writeIntegrationMemoryFixture(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "integration_memdump.bin")
	data := []byte{
		0x4d, 0x5a, 0x90, 0x00,
		'M', 'e', 'm', 'o', 'r', 'y', '-', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't',
		0x90, 0x90, 0x90,
		0x31, 0xc0, 0x50, 0x68,
		'X', 'Y', 'Z',
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write mem fixture: %v", err)
	}
	return path
}
