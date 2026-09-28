package builtin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"mutant/object"
)

// TestTheHTTPBuiltinsDoNotFollowTheProxyVariables holds http_get, http_post,
// http_request and lua_run_http to the host they are given. They went through
// net/http's default transport, which sends a request through whatever proxy
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY name, so whoever set the examiner's
// environment saw every fetch and upload, and could rewrite a plain-HTTP answer
// (M26-NET-010).
//
// net/http reads those variables once, the first time any request in the
// process asks for a proxy, so the requests below prove something only when
// this test runs before any other request does -- on its own, or first. The
// transport is checked as well, which holds in any order.
func TestTheHTTPBuiltinsDoNotFollowTheProxyVariables(t *testing.T) {
	client, err := httpClient()
	if err != nil {
		t.Fatalf("build the client: %v", err)
	}
	if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		t.Errorf("the http_* builtins' transport is %T and asks for a proxy; it must name none", client.Transport)
	}

	var reached atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = io.WriteString(w, "from-the-proxy")
	}))
	defer proxy.Close()

	variables := map[string]string{"HTTP_PROXY": proxy.URL, "HTTPS_PROXY": proxy.URL, "NO_PROXY": ""}
	for name, value := range variables {
		t.Setenv(name, value)
	}

	// An .invalid name never resolves (RFC 6761), so a request that does not go
	// through the proxy fails before it leaves the machine. net/http never
	// proxies a loopback address, which is why the target cannot be local.
	const target = "http://ioc-feed.mutant-review.invalid/list.txt"
	calls := []struct {
		name string
		call func() object.Object
	}{
		{"http_get", func() object.Object { return HttpGet(stringObj(target)) }},
		{"http_post", func() object.Object { return HttpPost(stringObj(target), stringObj("evidence")) }},
		{"http_request", func() object.Object {
			return HttpRequest(stringObj("GET"), stringObj(target), stringObj(""), makeHashObject(map[string]object.Object{}))
		}},
		{"lua_run_http", func() object.Object { return LuaRunHTTP(stringObj(target)) }},
	}
	for _, c := range calls {
		before := reached.Load()
		result, errObj := unwrapPairNoFatal(c.call())
		if reached.Load() != before {
			t.Errorf("%s went through the proxy HTTP_PROXY names", c.name)
		}
		if errObj == nil && strings.Contains(result.Inspect(), "from-the-proxy") {
			t.Errorf("%s returned the proxy's answer: %s", c.name, result.Inspect())
		}
	}
}
