package builtin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"mutant/object"
)

// TestAPolicyCannotCallHTTPSend holds a Rego policy to the input it is given.
// OPA evaluated a policy with every builtin it has, http.send among them, and
// http.send's client takes its proxy from HTTP_PROXY, HTTPS_PROXY and NO_PROXY
// and its default timeout from HTTP_SEND_TIMEOUT (M26-DAT-030). policy_load
// evaluates a policy's queries to validate it, so loading one was enough to
// send the request. A policy that calls http.send, in its module or in a query,
// is refused now, before anything is sent: the http_* builtins fetch, and the
// policy reads what they fetched from its input.
func TestAPolicyCannotCallHTTPSend(t *testing.T) {
	var reached atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, `{"allow": true}`)
	}))
	defer server.Close()

	fetch := fmt.Sprintf(`http.send({"method": "get", "url": %q})`, server.URL)
	fetching := makeHashObject(map[string]object.Object{
		"module": stringObj("package fetch\n\nresponse := " + fetch + "\n\n" +
			"decision := response.body\n\nallow := response.status_code == 200\n\nrules := [\"decision\"]\n"),
	})
	asking := makeHashObject(map[string]object.Object{
		"module":     stringObj("package ask\n\ndecision := 1\n\nallow := true\n\nrules := []\n"),
		"eval_query": stringObj(fetch + ".body"),
	})
	input := makeHashObject(map[string]object.Object{})

	for _, tc := range []struct {
		name string
		call func() object.Object
	}{
		{"policy_load", func() object.Object { return PolicyLoad(stringObj("fetch"), fetching) }},
		{"policy_eval", func() object.Object { return PolicyEval(fetching, input) }},
		{"policy_allow", func() object.Object { return PolicyAllow(fetching, input) }},
		{"policy_trace", func() object.Object { return PolicyTrace(fetching, input) }},
		{"policy_rules", func() object.Object { return PolicyRules(fetching) }},
		{"policy_eval of a query", func() object.Object { return PolicyEval(asking, input) }},
	} {
		before := reached.Load()
		_, errObj := unwrapPairNoFatal(tc.call())
		if reached.Load() != before {
			t.Errorf("%s: the policy's http.send reached the server", tc.name)
		}
		if errObj == nil || !strings.Contains(errObj.Inspect(), "http.send") {
			t.Errorf("%s: want a refusal naming http.send, got %v", tc.name, errObj)
		}
	}
}

// TestAPolicyCannotFetchASchema closes the other way a policy reached the
// network. json.match_schema and json.verify_schema fetch a schema's remote
// $ref with net/http's default client, so with http.send gone a policy could
// still send a request, and it went through the proxy HTTP_PROXY names
// (M26-DAT-032). Both are refused, the way http.send is.
func TestAPolicyCannotFetchASchema(t *testing.T) {
	var reached atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, `{"type": "object"}`)
	}))
	defer server.Close()

	remote := fmt.Sprintf(`{"$ref": %q}`, server.URL+"/schema.json")
	for name, call := range map[string]string{
		"json.match_schema":  `json.match_schema({"a": 1}, ` + remote + `)`,
		"json.verify_schema": `json.verify_schema(` + remote + `)`,
	} {
		policy := makeHashObject(map[string]object.Object{
			"module": stringObj("package schema\n\ndecision := " + call + "\n\nallow := true\n\nrules := []\n"),
		})
		before := reached.Load()
		_, errObj := unwrapPairNoFatal(PolicyEval(policy, makeHashObject(map[string]object.Object{})))
		if reached.Load() != before {
			t.Errorf("%s fetched the schema's $ref", name)
		}
		if errObj == nil || !strings.Contains(errObj.Inspect(), name) {
			t.Errorf("%s: want a refusal naming it, got %v", name, errObj)
		}
	}
}
