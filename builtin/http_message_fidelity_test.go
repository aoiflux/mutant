package builtin

// Four defects, one subject: an HTTP answer or an HTTP message that says
// something other than what arrived.
//
//   - M26-NET-015 the client followed up to ten redirects, across hosts and
//     out of https, and the result named no URL at all, so a fetch answered by
//     somewhere else read as the answer for the URL asked.
//   - M26-NET-016 http_build_request and http_build_response wrote whatever
//     Content-Length the caller's hash held, so parse, change the body, rebuild
//     -- the one thing these builtins are for -- produced a message whose
//     declared length disagreed with it.
//   - M26-NET-021 the response body was read with an unbounded io.ReadAll.
//   - The Set-Cookie fold, found while measuring the three above.
//
// Every expectation below is written from the platform's documented behaviour
// or counted by the test itself. Nothing reads its expectation from the code
// under test: the cookie values are literals, the lengths come from Go's own
// len, and the hop count is counted by the handler rather than by the field it
// is checked against.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mutant/object"
)

// fidelityHash unwraps a builtin's pair and insists the value is a hash.
func fidelityHash(t *testing.T, value object.Object) *object.Hash {
	t.Helper()
	inner, errObj := unwrapPair(t, value)
	if errObj != nil {
		t.Fatalf("builtin refused unexpectedly: %s", errObj.Message)
	}
	h, ok := inner.(*object.Hash)
	if !ok {
		t.Fatalf("builtin did not return a hash. got=%T", inner)
	}
	return h
}

// fidelityString unwraps a builtin's pair and insists the value is a string.
func fidelityString(t *testing.T, value object.Object) string {
	t.Helper()
	inner, errObj := unwrapPair(t, value)
	if errObj != nil {
		t.Fatalf("builtin refused unexpectedly: %s", errObj.Message)
	}
	s, ok := inner.(*object.String)
	if !ok {
		t.Fatalf("builtin did not return a string. got=%T", inner)
	}
	return s.Value
}

// fidelityRefusal unwraps a builtin's pair and insists it refused.
func fidelityRefusal(t *testing.T, what string, value object.Object) string {
	t.Helper()
	_, errObj := unwrapPair(t, value)
	if errObj == nil {
		t.Fatalf("%s: expected a refusal, got none", what)
	}
	return errObj.Message
}

// withBody copies a parsed message hash and replaces one field.
func withBody(parsed *object.Hash, key string, value object.Object) *object.Hash {
	pairs := make(map[object.HashKey]object.HashPair, len(parsed.Pairs)+1)
	for k, v := range parsed.Pairs {
		pairs[k] = v
	}
	keyObj := &object.String{Value: key}
	pairs[keyObj.HashKey()] = object.HashPair{Key: keyObj, Value: value}
	return &object.Hash{Pairs: pairs}
}

// ---------------------------------------------------------------- M26-NET-015

// TestARedirectedAnswerNamesTheURLThatGaveIt is the row's own regression test:
// server A replies 302 to server B, and the result has to say that B answered.
func TestARedirectedAnswerNamesTheURLThatGaveIt(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "from-B-%s", r.Method)
	}))
	defer b.Close()

	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/landing", http.StatusFound)
	}))
	defer a.Close()

	h := fidelityHash(t, HttpGet(&object.String{Value: a.URL + "/ioc"}))

	if got := hStr(t, h, "body"); got != "from-B-GET" {
		t.Fatalf("body came from somewhere unexpected: %q", got)
	}
	// The whole defect: a result that could not be told apart from one A gave.
	want := b.URL + "/landing"
	if got := hStr(t, h, "final_url"); got != want {
		t.Errorf("final_url = %q, want %q -- the answer came from the other host", got, want)
	}
	if got := hInt(t, h, "redirects"); got != 1 {
		t.Errorf("redirects = %d, want 1", got)
	}
	if got := hInt(t, h, "status"); got != 200 {
		t.Errorf("status = %d, want 200", got)
	}
}

// TestAPostThatBecameAGetSaysSo. net/http turns a POST into a GET on 301, 302
// and 303, as RFC 9110 section 15.4 describes and every browser does. The
// method is not changed back -- it is reported, because a script that believes
// its POST was delivered is wrong in a way nothing else in the result shows.
func TestAPostThatBecameAGetSaysSo(t *testing.T) {
	var methodSeen string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodSeen = r.Method
		fmt.Fprint(w, "landed")
	}))
	defer b.Close()

	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL+"/landing", http.StatusFound)
	}))
	defer a.Close()

	h := fidelityHash(t, HttpPost(
		&object.String{Value: a.URL + "/submit"},
		&object.String{Value: "payload"},
		&object.String{Value: "text/plain"}))

	// What the far end actually received, counted by the handler.
	if methodSeen != "GET" {
		t.Fatalf("the second server saw %q; this test is about the case where a POST becomes a GET", methodSeen)
	}
	if got := hStr(t, h, "final_method"); got != "GET" {
		t.Errorf("final_method = %q, want %q -- the POST did not survive the redirect", got, "GET")
	}
}

// TestAnAnswerWithNoRedirectNamesItself. The fields are not only for the
// redirect case: a direct answer has to name its own URL and report no hops, or
// a script cannot use them without knowing in advance which case it is in.
func TestAnAnswerWithNoRedirectNamesItself(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "direct")
	}))
	defer srv.Close()

	asked := srv.URL + "/evidence?case=1"
	h := fidelityHash(t, HttpGet(&object.String{Value: asked}))

	if got := hStr(t, h, "final_url"); got != asked {
		t.Errorf("final_url = %q, want %q", got, asked)
	}
	if got := hInt(t, h, "redirects"); got != 0 {
		t.Errorf("redirects = %d, want 0", got)
	}
	if got := hStr(t, h, "final_method"); got != "GET" {
		t.Errorf("final_method = %q, want GET", got)
	}
}

// TestTheHopCountIsTheNumberOfHops, counted by the server rather than read off
// the field being checked.
func TestTheHopCountIsTheNumberOfHops(t *testing.T) {
	const chain = 3
	served := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served < chain {
			served++
			http.Redirect(w, r, fmt.Sprintf("%s/hop%d", srv.URL, served), http.StatusFound)
			return
		}
		fmt.Fprint(w, "arrived")
	}))
	defer srv.Close()

	h := fidelityHash(t, HttpGet(&object.String{Value: srv.URL + "/start"}))
	if served != chain {
		t.Fatalf("the server redirected %d times; this test needs %d", served, chain)
	}
	if got := hInt(t, h, "redirects"); got != int64(chain) {
		t.Errorf("redirects = %d, want %d", got, chain)
	}
}

// TestARedirectOutOfTLSIsRefused tests checkHTTPRedirect directly.
//
// Not through a server: httptest.NewTLSServer signs its certificate itself, and
// this client verifies certificates against clientRootCAs, so the fetch is
// refused at the handshake and the redirect never happens -- which was measured
// before this test was written. The decision is a pure function of the two
// URLs, so it is tested as one, with the request pair built the way net/http
// builds it (the hop being considered, and the chain so far).
func TestARedirectOutOfTLSIsRefused(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return u
	}
	hop := func(from, to string) error {
		return checkHTTPRedirect(
			&http.Request{URL: mustParse(to)},
			[]*http.Request{{URL: mustParse(from)}})
	}

	err := hop("https://evidence.example/ioc", "http://elsewhere.example/landing")
	if err == nil {
		t.Fatal("https -> http was followed; TLS was discarded silently")
	}
	for _, want := range []string{"TLS", "https"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %s", want, err.Error())
		}
	}

	// The other direction is an upgrade, and the same host over https is the
	// ordinary case. Neither is refused.
	if err := hop("http://evidence.example/ioc", "https://evidence.example/ioc"); err != nil {
		t.Errorf("http -> https was refused: %v", err)
	}
	if err := hop("https://evidence.example/ioc", "https://cdn.example/ioc"); err != nil {
		t.Errorf("https -> https on another host was refused: %v", err)
	}
	// Cross-host over plain http is how most of the web serves a file.
	if err := hop("http://evidence.example/ioc", "http://cdn.example/ioc"); err != nil {
		t.Errorf("http -> http on another host was refused: %v", err)
	}
}

// TestTheHopBudgetIsOurOwn. Setting a CheckRedirect replaces net/http's default
// stop-after-ten outright, so the cap has to be enforced here or the chain
// becomes unbounded. The budget is checked at its boundary, not at its value.
func TestTheHopBudgetIsOurOwn(t *testing.T) {
	chain := make([]*http.Request, httpMaxRedirects)
	for i := range chain {
		chain[i] = &http.Request{URL: &url.URL{Scheme: "http", Host: "h", Path: fmt.Sprintf("/%d", i)}}
	}
	next := &http.Request{URL: &url.URL{Scheme: "http", Host: "h", Path: "/next"}}

	if err := checkHTTPRedirect(next, chain[:len(chain)-1]); err != nil {
		t.Errorf("hop %d of %d was refused: %v", len(chain), httpMaxRedirects, err)
	}
	if err := checkHTTPRedirect(next, chain); err == nil {
		t.Errorf("hop %d was followed; the budget is %d", len(chain)+1, httpMaxRedirects)
	}
}

// ---------------------------------------------------------------- M26-NET-021

// TestAResponseBodyPastTheCapIsRefused, at the boundary from both sides. The
// read used to be an unbounded io.ReadAll, so a 48 MiB answer arrived whole and
// an endless one was read until the request timeout.
func TestAResponseBodyPastTheCapIsRefused(t *testing.T) {
	serve := func(t *testing.T, size int) *httptest.Server {
		t.Helper()
		chunk := strings.Repeat("A", 1<<20)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
			written := 0
			for written < size {
				n := len(chunk)
				if size-written < n {
					n = size - written
				}
				if _, err := w.Write([]byte(chunk[:n])); err != nil {
					return
				}
				written += n
			}
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	t.Run("at the cap it is whole", func(t *testing.T) {
		srv := serve(t, maxHTTPBodyBytes)
		h := fidelityHash(t, HttpGet(&object.String{Value: srv.URL}))
		if got := len(hStr(t, h, "body")); got != maxHTTPBodyBytes {
			t.Errorf("body is %d bytes, want %d -- a body that fits must arrive whole", got, maxHTTPBodyBytes)
		}
		if got := hStr(t, h, "error"); got != "" {
			t.Errorf("error = %q, want empty", got)
		}
	})

	t.Run("one byte past it is refused", func(t *testing.T) {
		srv := serve(t, maxHTTPBodyBytes+1)
		value := HttpGet(&object.String{Value: srv.URL})

		// The pair's error fires, which is how all three builtins report this.
		inner, errObj := unwrapPair(t, value)
		if errObj == nil {
			t.Fatal("a body past the cap returned no error")
		}
		h, ok := inner.(*object.Hash)
		if !ok {
			t.Fatalf("no hash beside the error. got=%T", inner)
		}
		if got := hStr(t, h, "body"); got != "" {
			t.Errorf("body holds %d bytes; a body cut at the cap must not be handed back", len(got))
		}
		// The status and headers did arrive and are not in doubt, which is what
		// tells this apart from a connection that never answered (status 0).
		if got := hInt(t, h, "status"); got != 200 {
			t.Errorf("status = %d, want 200", got)
		}
		if !strings.Contains(hStr(t, h, "error"), fmt.Sprintf("%d", maxHTTPBodyBytes)) {
			t.Errorf("the error does not name the cap: %q", hStr(t, h, "error"))
		}
	})
}

// ------------------------------------------------------ the Set-Cookie fold

// TestTwoSetCookieLinesStayTwo. RFC 9110 section 5.3 permits combining a
// repeated field into one comma-separated value only where the value is defined
// as a comma-separated list, and names Set-Cookie as the field that is not; RFC
// 6265 section 3 forbids the fold from the server's side. A cookie's Expires
// date holds a comma of its own, so the join cannot be undone by anything.
func TestTwoSetCookieLinesStayTwo(t *testing.T) {
	const first = "session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/"
	const second = "csrf=xyz; HttpOnly"

	raw := "HTTP/1.1 200 OK\r\n" +
		"Set-Cookie: " + first + "\r\n" +
		"Set-Cookie: " + second + "\r\n" +
		"X-Note: one\r\n" +
		"X-Note: two\r\n" +
		"Content-Length: 2\r\n" +
		"\r\n" +
		"ok"

	parsed := fidelityHash(t, HTTPParseResponse(&object.String{Value: raw}))
	headers, ok := hashField(t, parsed, "headers").(*object.Hash)
	if !ok {
		t.Fatal("headers is not a hash")
	}

	cookies, ok := hashValueByKey(headers, "Set-Cookie").(*object.Array)
	if !ok {
		t.Fatalf("Set-Cookie is not a list: %s", hashValueByKey(headers, "Set-Cookie").Inspect())
	}
	if len(cookies.Elements) != 2 {
		t.Fatalf("Set-Cookie holds %d values, want 2", len(cookies.Elements))
	}
	// In order, and byte for byte: the comma inside the first one is the reason
	// a joined value could not be split back apart.
	for i, want := range []string{first, second} {
		got, ok := cookies.Elements[i].(*object.String)
		if !ok {
			t.Fatalf("Set-Cookie[%d] is not a string", i)
		}
		if got.Value != want {
			t.Errorf("Set-Cookie[%d] = %q, want %q", i, got.Value, want)
		}
	}

	// A field whose value IS a comma-separated list keeps the old behaviour,
	// because combining it is both legal and reversible.
	if got := hStr(t, headers, "X-Note"); got != "one, two" {
		t.Errorf("X-Note = %q, want %q", got, "one, two")
	}

	// And the rebuild puts both lines back on the wire, in order.
	wire := fidelityString(t, HTTPBuildResponse(parsed))
	if got := strings.Count(wire, "Set-Cookie:"); got != 2 {
		t.Fatalf("rebuilt message carries %d Set-Cookie lines, want 2:\n%s", got, wire)
	}
	if a, b := strings.Index(wire, first), strings.Index(wire, second); a < 0 || b < 0 || a > b {
		t.Errorf("the two cookies are missing or out of order:\n%s", wire)
	}
}

// TestOneSetCookieIsStillAList. A field whose type depended on how many values
// happened to arrive would make every script handle both shapes.
func TestOneSetCookieIsStillAList(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nSet-Cookie: only=1\r\nContent-Length: 0\r\n\r\n"
	parsed := fidelityHash(t, HTTPParseResponse(&object.String{Value: raw}))
	headers := hashField(t, parsed, "headers").(*object.Hash)

	arr, ok := hashValueByKey(headers, "Set-Cookie").(*object.Array)
	if !ok {
		t.Fatalf("a single Set-Cookie is not a list: %s", hashValueByKey(headers, "Set-Cookie").Inspect())
	}
	if len(arr.Elements) != 1 {
		t.Fatalf("Set-Cookie holds %d values, want 1", len(arr.Elements))
	}
}

// TestHttpGetReportsCookiesTheSameWay. The fetching builtins built their header
// hash inline, separately from the interception builtins, so the same response
// was described two ways. They share one reading now.
func TestHttpGetReportsCookiesTheSameWay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
		w.Header().Add("Set-Cookie", "b=2; HttpOnly")
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	h := fidelityHash(t, HttpGet(&object.String{Value: srv.URL}))
	headers, ok := hashField(t, h, "headers").(*object.Hash)
	if !ok {
		t.Fatal("headers is not a hash")
	}
	arr, ok := hashValueByKey(headers, "Set-Cookie").(*object.Array)
	if !ok {
		t.Fatalf("Set-Cookie is not a list: %s", hashValueByKey(headers, "Set-Cookie").Inspect())
	}
	if len(arr.Elements) != 2 {
		t.Fatalf("http_get reported %d cookies, the server sent 2", len(arr.Elements))
	}
}

// ---------------------------------------------------------------- M26-NET-016

// TestChangingABodyDoesNotLeaveTheOldLength is the defect in the shape a script
// meets it: parse, change the body, rebuild.
func TestChangingABodyDoesNotLeaveTheOldLength(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello"
	parsed := fidelityHash(t, HTTPParseRequest(&object.String{Value: raw}))
	if got := hStr(t, parsed, "body"); got != "hello" {
		t.Fatalf("parsed body = %q, want %q", got, "hello")
	}

	const replacement = "hello, world"
	changed := withBody(parsed, "body", &object.String{Value: replacement})

	msg := fidelityRefusal(t, "http_build_request after a body change",
		HTTPBuildRequest(changed))
	for _, want := range []string{"5", fmt.Sprintf("%d", len(replacement)), "Content-Length"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}

	// And the way out the refusal names: drop the header, get a correct one.
	headers := hashField(t, parsed, "headers").(*object.Hash)
	stripped := make(map[string]object.Object, len(headers.Pairs))
	for _, pair := range headers.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok || strings.EqualFold(key.Value, "Content-Length") {
			continue
		}
		stripped[key.Value] = pair.Value
	}
	withoutLength := withBody(changed, "headers", makeHashObject(stripped))

	wire := fidelityString(t, HTTPBuildRequest(withoutLength))
	want := fmt.Sprintf("Content-Length: %d\r\n", len(replacement))
	if !strings.Contains(wire, want) {
		t.Errorf("rebuilt message does not declare %d bytes:\n%s", len(replacement), wire)
	}
	if !strings.HasSuffix(wire, "\r\n\r\n"+replacement) {
		t.Errorf("rebuilt message does not end in the new body:\n%s", wire)
	}
}

// TestALengthThatAgreesIsWrittenThrough. The check must not refuse the ordinary
// case: a message relayed unchanged keeps its own header.
func TestALengthThatAgreesIsWrittenThrough(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello"
	parsed := fidelityHash(t, HTTPParseRequest(&object.String{Value: raw}))

	wire := fidelityString(t, HTTPBuildRequest(parsed))
	if got := strings.Count(wire, "Content-Length:"); got != 1 {
		t.Errorf("rebuilt message carries %d Content-Length headers, want 1:\n%s", got, wire)
	}
	if !strings.Contains(wire, "Content-Length: 5\r\n") {
		t.Errorf("rebuilt message lost its length:\n%s", wire)
	}
}

// TestAResponseLengthThatDisagreesIsRefused, the same check on the other builder.
func TestAResponseLengthThatDisagreesIsRefused(t *testing.T) {
	const body = "0123456789"
	resp := makeHashObject(map[string]object.Object{
		"status":  intObj(200),
		"body":    stringObj(body),
		"headers": makeHashObject(map[string]object.Object{"Content-Length": stringObj("2")}),
	})
	msg := fidelityRefusal(t, "http_build_response", HTTPBuildResponse(resp))
	for _, want := range []string{"2", fmt.Sprintf("%d", len(body))} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name %q: %s", want, msg)
		}
	}
}

// TestALengthThatIsNotANumberIsRefused, and two of them likewise: a message
// declares its length once, and two Content-Length headers are the other half
// of how a connection is desynchronised.
func TestALengthThatIsNotANumberIsRefused(t *testing.T) {
	build := func(value object.Object) object.Object {
		return HTTPBuildResponse(makeHashObject(map[string]object.Object{
			"status":  intObj(200),
			"body":    stringObj("ok"),
			"headers": makeHashObject(map[string]object.Object{"Content-Length": value}),
		}))
	}

	msg := fidelityRefusal(t, "a non-numeric Content-Length", build(stringObj("two")))
	if !strings.Contains(msg, "not a number") {
		t.Errorf("unexpected refusal: %s", msg)
	}

	msg = fidelityRefusal(t, "two Content-Length headers",
		build(stringListObj([]string{"2", "3"})))
	if !strings.Contains(msg, "two Content-Length") {
		t.Errorf("unexpected refusal: %s", msg)
	}

	// A correct one as a one-element list is the shape a parsed message would
	// have if the field were ever treated as a list, and it must still pass.
	if _, errObj := unwrapPair(t, build(stringListObj([]string{"2"}))); errObj != nil {
		t.Errorf("a single correct length as a list was refused: %s", errObj.Message)
	}
}

// TestAParsedMessageRebuildsToItself is the invariant the other tests are
// specimens of: for a message these builtins can parse, parse(build(parse(x)))
// has the same body and the same header values as parse(x). Nothing in this
// test names a number.
func TestAParsedMessageRebuildsToItself(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Set-Cookie: a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT\r\n" +
		"Set-Cookie: b=2\r\n" +
		"Content-Length: 13\r\n" +
		"\r\n" +
		`{"ok":true}  `

	once := fidelityHash(t, HTTPParseResponse(&object.String{Value: raw}))
	wire := fidelityString(t, HTTPBuildResponse(once))
	twice := fidelityHash(t, HTTPParseResponse(&object.String{Value: wire}))

	if a, b := hStr(t, once, "body"), hStr(t, twice, "body"); a != b {
		t.Errorf("body changed across a round trip: %q then %q", a, b)
	}
	if a, b := hInt(t, once, "status"), hInt(t, twice, "status"); a != b {
		t.Errorf("status changed across a round trip: %d then %d", a, b)
	}

	first := hashField(t, once, "headers").(*object.Hash)
	second := hashField(t, twice, "headers").(*object.Hash)
	for _, pair := range first.Pairs {
		key := pair.Key.(*object.String).Value
		got := hashValueByKey(second, key)
		if got == nil {
			t.Errorf("header %q did not survive the round trip", key)
			continue
		}
		if got.Inspect() != pair.Value.Inspect() {
			t.Errorf("header %q = %s after the round trip, was %s", key, got.Inspect(), pair.Value.Inspect())
		}
	}
}

// --------------------------------------------- statuses that have no body

// TestARelayedNotModifiedKeepsItsLength. A 304 carries no body and may still
// declare a Content-Length, which describes the cached representation the
// recipient already holds and which an interception proxy never sees (RFC 9110
// sections 15.4.5 and 8.6). So the header cannot be compared with the body, and
// the length check had to learn that: it refused to rebuild a 304 when it was
// first written, which would have broken relaying the most ordinary response
// there is. Measured, not assumed -- this is what the probe found.
func TestARelayedNotModifiedKeepsItsLength(t *testing.T) {
	raw := "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nContent-Length: 1234\r\n\r\n"
	parsed := fidelityHash(t, HTTPParseResponse(&object.String{Value: raw}))
	if got := hStr(t, parsed, "body"); got != "" {
		t.Fatalf("a 304 parsed to a body of %d bytes", len(got))
	}

	wire := fidelityString(t, HTTPBuildResponse(parsed))
	if !strings.Contains(wire, "Content-Length: 1234\r\n") {
		t.Errorf("the cached entity's length did not survive the relay:\n%s", wire)
	}
	if got := strings.Count(wire, "Content-Length:"); got != 1 {
		t.Errorf("rebuilt 304 carries %d Content-Length headers, want 1:\n%s", got, wire)
	}
	if !strings.HasSuffix(wire, "\r\n\r\n") {
		t.Errorf("rebuilt 304 has something after its head:\n%q", wire)
	}
}

// TestABodylessStatusIsNotGivenALength. RFC 9110 section 8.6: a server MUST NOT
// send Content-Length in a 1xx or a 204. The builder added one unconditionally,
// so a 101 relayed through an interception proxy went back to the client as a
// malformed WebSocket handshake. This one was not in any row; the probe for the
// 304 found it.
func TestABodylessStatusIsNotGivenALength(t *testing.T) {
	for _, raw := range []string{
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.1 100 Continue\r\n\r\n",
	} {
		line := strings.SplitN(raw, "\r\n", 2)[0]
		parsed := fidelityHash(t, HTTPParseResponse(&object.String{Value: raw}))
		wire := fidelityString(t, HTTPBuildResponse(parsed))
		if strings.Contains(wire, "Content-Length") {
			t.Errorf("%s was given a Content-Length:\n%q", line, wire)
		}
	}

	// A 200 with no body still gets one, because for a 200 the absence of a
	// body is itself a fact the length states.
	parsed := fidelityHash(t, HTTPParseResponse(
		&object.String{Value: "HTTP/1.1 200 OK\r\n\r\n"}))
	wire := fidelityString(t, HTTPBuildResponse(parsed))
	if !strings.Contains(wire, "Content-Length: 0\r\n") {
		t.Errorf("an empty 200 lost its Content-Length: 0:\n%q", wire)
	}
}

// TestABodyOnABodylessStatusIsRefused. Whichever way the length is written,
// bytes after a status that says there is no body are read by the recipient as
// the beginning of the next message.
func TestABodyOnABodylessStatusIsRefused(t *testing.T) {
	for _, status := range []int64{101, 204, 304} {
		msg := fidelityRefusal(t, fmt.Sprintf("a %d with a body", status),
			HTTPBuildResponse(makeHashObject(map[string]object.Object{
				"status":  intObj(status),
				"body":    stringObj("oops"),
				"headers": makeHashObject(map[string]object.Object{}),
			})))
		if !strings.Contains(msg, fmt.Sprintf("%d", status)) {
			t.Errorf("the refusal does not name the status: %s", msg)
		}
	}

	// And the ordinary case is untouched: a 200 with a body builds.
	if _, errObj := unwrapPair(t, HTTPBuildResponse(makeHashObject(map[string]object.Object{
		"status":  intObj(200),
		"body":    stringObj("fine"),
		"headers": makeHashObject(map[string]object.Object{}),
	}))); errObj != nil {
		t.Errorf("a 200 with a body was refused: %s", errObj.Message)
	}
}
