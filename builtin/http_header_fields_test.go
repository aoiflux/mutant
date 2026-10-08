package builtin

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"mutant/object"
)

// The shared half of M26-NET-028: the cap itself, what it counts, and the
// http_get / http_post / http_request family, whose head budget is not the
// proxy's. That family sends through httpClient, whose transport sets no
// MaxResponseHeaderBytes, so net/http's own default of 10 MiB applies
// (net/http/transport.go:333 in go1.26.6) -- ten times the head the
// interception builtins accept, for ten times the field count, and it needs no
// proxy and no intercepted connection, only a server that answers a fetch.

// TestTheFieldCapIsTheDocumentedValue pins the number itself. The cap is a
// published limit: it is rendered into docs/LIMITS_REFERENCE.md and a script
// that sends a hundred fields has to keep working, so changing it is a decision
// and not an edit.
//
// The expectation is written out rather than read from the constant under test,
// which is the whole point of the test.
func TestTheFieldCapIsTheDocumentedValue(t *testing.T) {
	if maxHTTPHeaderFields != 100 {
		t.Fatalf("maxHTTPHeaderFields is %d; 100 is Apache httpd's "+
			"LimitRequestFields default and the owner's decision of 2026-10-07",
			maxHTTPHeaderFields)
	}
}

// TestTheFieldCountCountsLinesAndNotNames is the counting rule on its own,
// away from any socket. http.Header is a map[string][]string: the obvious
// len(header) counts distinct names, and a head that spells one name a hundred
// thousand times is one name. The cap has to see a hundred thousand.
func TestTheFieldCountCountsLinesAndNotNames(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		want   int
	}{
		{"nothing", http.Header{}, 0},
		{"nil", nil, 0},
		{"three names", http.Header{
			"A": {"1"}, "B": {"2"}, "C": {"3"},
		}, 3},
		{"one name, three values", http.Header{"A": {"1", "2", "3"}}, 3},
		{"a name with no values at all", http.Header{"A": {}}, 0},
		{"two names, five values", http.Header{
			"A": {"1", "2"}, "B": {"3", "4", "5"},
		}, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := httpHeaderFieldCount(c.header); got != c.want {
				t.Fatalf("httpHeaderFieldCount = %d, want %d", got, c.want)
			}
		})
	}

	// The case that matters, stated as itself: one name, more values than the
	// cap allows. len() accepts it; the count refuses it.
	repeated := http.Header{"X-Same": make([]string, maxHTTPHeaderFields+1)}
	if len(repeated) != 1 {
		t.Fatalf("one name should be one map entry, got %d", len(repeated))
	}
	if got := httpHeaderFieldCount(repeated); got != maxHTTPHeaderFields+1 {
		t.Fatalf("httpHeaderFieldCount = %d, want %d", got, maxHTTPHeaderFields+1)
	}
	if err := checkHTTPHeaderFields(repeated); err == nil {
		t.Fatal("a single name repeated past the cap must be refused")
	}
}

// TestTheCheckRefusesOnePastTheCapAndNotAtIt is the off-by-one on the check
// itself, so the boundary is pinned once in one place as well as through each
// builtin that calls it.
func TestTheCheckRefusesOnePastTheCapAndNotAtIt(t *testing.T) {
	atCap := make(http.Header, maxHTTPHeaderFields)
	for i := 0; i < maxHTTPHeaderFields; i++ {
		atCap["X-F"+strconv.Itoa(i)] = []string{"1"}
	}
	if err := checkHTTPHeaderFields(atCap); err != nil {
		t.Fatalf("exactly %d fields is within the cap: %s", maxHTTPHeaderFields, err)
	}

	atCap["X-One-More"] = []string{"1"}
	err := checkHTTPHeaderFields(atCap)
	if err == nil {
		t.Fatalf("%d fields is one past the cap and must be refused",
			maxHTTPHeaderFields+1)
	}
	if !strings.Contains(err.Error(), "header fields") {
		t.Fatalf("the refusal should say what it counted, got %q", err)
	}
	for _, want := range []string{
		strconv.Itoa(maxHTTPHeaderFields + 1), strconv.Itoa(maxHTTPHeaderFields),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %s: %q", want, err)
		}
	}
}

// headerFieldServer answers every request with `fields` numbered response
// header fields and a short body.
func headerFieldServer(t *testing.T, fields int) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i < fields; i++ {
			w.Header().Set("X-F"+strconv.Itoa(i), "1")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)
	return server
}

// TestHTTPGetRefusesAResponseHeadPastTheFieldCap is the http_* client family's
// half. It is a separate site from the interception builtins, it has no byte
// bound of its own beyond net/http's 10 MiB transport default, and it is
// reachable by fetching from any server -- so a cap on the proxy with this
// uncapped would be half a fix.
//
// The response the server builds carries the fields it was asked for plus the
// ones net/http adds (Content-Type, Date, Content-Length), so the count in the
// refusal is above the number asked for. The assertion is on the refusal and on
// the cap, not on the exact total, because the added fields are net/http's to
// choose and a test that pinned them would fail on an unrelated Go upgrade.
func TestHTTPGetRefusesAResponseHeadPastTheFieldCap(t *testing.T) {
	server := headerFieldServer(t, maxHTTPHeaderFields+1)

	result, errObj := unwrapPair(t, HttpGet(stringObj(server.URL)))
	if errObj == nil {
		t.Fatal("a response head of more fields than the cap allows must be refused")
	}
	if !strings.Contains(errObj.Message, "header fields") {
		t.Fatalf("expected the field-count refusal, got %q", errObj.Message)
	}
	if !strings.Contains(errObj.Message, strconv.Itoa(maxHTTPHeaderFields)) {
		t.Fatalf("the refusal does not name the cap (%d): %q",
			maxHTTPHeaderFields, errObj.Message)
	}

	// http_get's refusals are a hash whose status is 0 and whose error field
	// carries the reason, beside the Mutant error. That shape is this family's
	// own and every other failure in it looks the same, so a script that reads
	// the hash rather than the error still sees a refusal and not an empty
	// success.
	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("http_get's refusal should still be a HASH, got %T", result)
	}
	if status := hashFieldInt(t, hash, "status"); status != 0 {
		t.Fatalf("a refused fetch has status 0, got %d", status)
	}
}

// TestHTTPGetKeepsAnOrdinaryResponseHead is the false-refusal guard for the
// client family: an ordinary answer is still read whole, with every field
// present. A cap that refuses real traffic is worse than the hole it closes.
func TestHTTPGetKeepsAnOrdinaryResponseHead(t *testing.T) {
	const fields = 10

	server := headerFieldServer(t, fields)

	result, errObj := unwrapPair(t, HttpGet(stringObj(server.URL)))
	if errObj != nil {
		t.Fatalf("a %d-field response is ordinary: %s", fields, errObj.Message)
	}
	hash, ok := result.(*object.Hash)
	if !ok {
		t.Fatalf("expected a HASH, got %T", result)
	}
	if status := hashFieldInt(t, hash, "status"); status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	headers := headersFromResult(t, hash)
	for i := 0; i < fields; i++ {
		name := "X-F" + strconv.Itoa(i)
		if _, ok := headers[name]; !ok {
			t.Fatalf("%s is missing from the headers hash", name)
		}
	}
}
