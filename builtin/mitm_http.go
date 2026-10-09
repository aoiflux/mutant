package builtin

// HTTP message inspection/interception builtins (dev-sec branch).
//
// These complement secure_net.go: once a connection is accepted (and, for
// HTTPS, TLS-terminated with a CA-signed leaf), these functions parse and
// rebuild HTTP requests/responses so a Mutant program can inspect or rewrite
// traffic in flight, mitmproxy-style. Parsing can work either on a raw string
// or directly on a connection handle, where correct Content-Length / chunked
// framing is handled by the standard library.

import (
	"bufio"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

// maxHTTPBodyBytes bounds the body an HTTP builtin hands back as one string:
// http_conn_read_request, http_conn_read_response, http_parse_request and
// http_parse_response, and also http_get, http_post and http_request, whose
// read had no bound of its own until M26-NET-021. A body past it is refused
// rather than cut. The peer at the other end decides how much it sends and is
// not trusted to be reasonable, and the body arrives as a VM variable, which is
// re-encrypted on every store. Refusing is what makes the answer honest: a
// clipped body returned as a whole one is a wrong result a script has no way to
// detect, which is what this cap used to produce (M26-NET-031). An intercepted
// message whose body may be larger is read with http_conn_read_request_head or
// http_conn_read_response_head plus net_conn_read, which leave the body on the
// connection and stream it in pieces; the three fetching builtins have no such
// streaming form, so a larger download is refused outright and the figure is
// what they are refused at.
//
//mutant:limit bytes
const maxHTTPBodyBytes = 32 << 20

// maxHTTPHeaderBytes bounds the request line and header block of one message.
// The body was capped and the head was not, so a peer could send a single
// header field of any length and have it read in full: an 8 MiB field grew the
// heap by 12 MiB and a 32 MiB field by 69 MiB, and both were accepted. A head
// is metadata about a body, and no real one is large.
//
// The value is net/http's own DefaultMaxHeaderBytes, so a message these
// builtins accept is one Go's HTTP server would accept too -- nginx and Apache
// both stop well below it. It is enforced on the socket beneath the buffered
// reader and released as soon as the head is parsed, because the two _head
// builtins deliberately leave the body on the connection for net_conn_read to
// stream and that read must not inherit a head's budget.
//
//mutant:limit bytes
const maxHTTPHeaderBytes = 1 << 20

// httpHeadReadSlack is what the socket is allowed beyond maxHTTPHeaderBytes
// while a head is being read. The parser draws through a bufio.Reader, which
// fills a whole buffer at a time, so the last fill can legitimately carry the
// start of a body past the end of the head. The figure is one bufio buffer,
// which is what net/http's own server adds to MaxHeaderBytes for this reason.
//
//mutant:limit bytes
const httpHeadReadSlack = 4096

// HTTPParseRequest parses a raw HTTP request into a structured hash.
// http_parse_request(raw STRING) -> HASH {method, url, path, host, proto, query, headers, body}
func HTTPParseRequest(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	raw, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_parse_request` must be STRING, got %s", args[0].Type()))
	}
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw.Value)))
	if err != nil {
		return resultAndError(nil, newError("http_parse_request: %s", err.Error()))
	}
	return resultAndError(requestToHash(BuiltinNameHttpParseRequest, req))
}

// HTTPParseResponse parses a raw HTTP response into a structured hash.
// http_parse_response(raw STRING) -> HASH {status, status_text, proto, headers, body}
func HTTPParseResponse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	raw, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_parse_response` must be STRING, got %s", args[0].Type()))
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw.Value)), nil)
	if err != nil {
		return resultAndError(nil, newError("http_parse_response: %s", err.Error()))
	}
	return resultAndError(responseToHash(BuiltinNameHttpParseResponse, resp))
}

// HTTPConnReadRequest reads exactly one HTTP request from a connection handle,
// honouring Content-Length / chunked framing.
// http_conn_read_request(handle INTEGER, timeout_ms INTEGER) -> HASH
func HTTPConnReadRequest(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout(BuiltinNameHttpConnReadRequest, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	mc.setReadLimit(maxHTTPHeaderBytes + httpHeadReadSlack)
	req, err := http.ReadRequest(mc.buffered())
	headTooLarge := mc.readLimitReached()
	mc.clearReadLimit()
	if err != nil {
		if headTooLarge {
			return resultAndError(nil, newError("http_conn_read_request: request head exceeds %d bytes", maxHTTPHeaderBytes))
		}
		return resultAndError(nil, newError("http_conn_read_request: %s", err.Error()))
	}
	return resultAndError(requestToHash(BuiltinNameHttpConnReadRequest, req))
}

// HTTPConnReadResponse reads exactly one HTTP response from a connection handle.
// http_conn_read_response(handle INTEGER, timeout_ms INTEGER) -> HASH
func HTTPConnReadResponse(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout(BuiltinNameHttpConnReadResponse, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	mc.setReadLimit(maxHTTPHeaderBytes + httpHeadReadSlack)
	resp, err := http.ReadResponse(mc.buffered(), nil)
	headTooLarge := mc.readLimitReached()
	mc.clearReadLimit()
	if err != nil {
		if headTooLarge {
			return resultAndError(nil, newError("http_conn_read_response: response head exceeds %d bytes", maxHTTPHeaderBytes))
		}
		return resultAndError(nil, newError("http_conn_read_response: %s", err.Error()))
	}
	return resultAndError(responseToHash(BuiltinNameHttpConnReadResponse, resp))
}

// HTTPConnReadRequestHead reads a request's line + headers WITHOUT consuming the
// body, leaving it on the connection so it can be streamed in chunks with
// net_conn_read (avoiding the 32 MiB whole-body cap). For a Content-Length body,
// exactly content_length raw bytes follow; a chunked body arrives chunk-encoded.
// http_conn_read_request_head(handle, timeout_ms) -> HASH {method,url,path,host,
//
//	proto,query,headers,content_length,chunked}
func HTTPConnReadRequestHead(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout(BuiltinNameHttpConnReadRequestHead, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	mc.setReadLimit(maxHTTPHeaderBytes + httpHeadReadSlack)
	req, err := http.ReadRequest(mc.buffered())
	headTooLarge := mc.readLimitReached()
	mc.clearReadLimit()
	if err != nil {
		if headTooLarge {
			return resultAndError(nil, newError("http_conn_read_request_head: request head exceeds %d bytes", maxHTTPHeaderBytes))
		}
		return resultAndError(nil, newError("http_conn_read_request_head: %s", err.Error()))
	}
	if fieldErr := checkHTTPHeaderFields(req.Header); fieldErr != nil {
		return resultAndError(nil, newError("http_conn_read_request_head: %s", fieldErr.Error()))
	}

	host := req.Host
	query := ""
	path := req.URL.Path
	if req.URL != nil {
		query = req.URL.RawQuery
		if host == "" {
			host = req.URL.Host
		}
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"method":         stringObj(req.Method),
		"url":            stringObj(req.URL.String()),
		"path":           stringObj(path),
		"host":           stringObj(host),
		"proto":          stringObj(req.Proto),
		"query":          stringObj(query),
		"headers":        headerToHash(req.Header),
		"content_length": intObj(req.ContentLength),
		"chunked":        boolObj(isChunked(req.TransferEncoding)),
	}), nil)
}

// HTTPConnReadResponseHead reads a response's status line + headers WITHOUT
// consuming the body, leaving it on the connection for streaming via
// net_conn_read. See HTTPConnReadRequestHead.
// http_conn_read_response_head(handle, timeout_ms) -> HASH {status,status_text,
//
//	proto,headers,content_length,chunked}
func HTTPConnReadResponseHead(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout(BuiltinNameHttpConnReadResponseHead, args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	mc.setReadLimit(maxHTTPHeaderBytes + httpHeadReadSlack)
	resp, err := http.ReadResponse(mc.buffered(), nil)
	headTooLarge := mc.readLimitReached()
	mc.clearReadLimit()
	if err != nil {
		if headTooLarge {
			return resultAndError(nil, newError("http_conn_read_response_head: response head exceeds %d bytes", maxHTTPHeaderBytes))
		}
		return resultAndError(nil, newError("http_conn_read_response_head: %s", err.Error()))
	}
	if fieldErr := checkHTTPHeaderFields(resp.Header); fieldErr != nil {
		return resultAndError(nil, newError("http_conn_read_response_head: %s", fieldErr.Error()))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"status":         intObj(int64(resp.StatusCode)),
		"status_text":    stringObj(http.StatusText(resp.StatusCode)),
		"proto":          stringObj(resp.Proto),
		"headers":        headerToHash(resp.Header),
		"content_length": intObj(resp.ContentLength),
		"chunked":        boolObj(isChunked(resp.TransferEncoding)),
	}), nil)
}

func isChunked(te []string) bool {
	for _, v := range te {
		if v == "chunked" {
			return true
		}
	}
	return false
}

// HTTPBuildRequest serialises a request hash back into wire bytes.
// http_build_request(request HASH) -> STRING
// Fields: method (default GET), url or path (default "/"), host, proto
// (default HTTP/1.1), headers (HASH), body (STRING). A Content-Length header is
// added when a body is present and the caller didn't supply one.
func HTTPBuildRequest(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	req := args[0]
	if _, ok := req.(*object.Hash); !ok {
		if _, ok := req.(*object.Struct); !ok {
			return resultAndError(nil, newError("argument 1 to `http_build_request` must be HASH or STRUCT, got %s", req.Type()))
		}
	}

	method := strings.ToUpper(optString(req, "method", "GET"))
	target := optString(req, "url", "")
	if target == "" {
		target = optString(req, "path", "/")
	}
	proto := optString(req, "proto", "HTTP/1.1")
	host := optString(req, "host", "")
	body := optString(req, "body", "")

	// Request-line target: keep absolute-form as-is (proxy request), otherwise
	// fall back to the path component.
	requestTarget := target
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") && target != "*" {
		if u, err := url.Parse(target); err == nil && u.Path != "" {
			requestTarget = u.RequestURI()
		}
	}

	var b strings.Builder
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(requestTarget)
	b.WriteString(" ")
	b.WriteString(proto)
	b.WriteString("\r\n")

	headers := headersToOrdered(req)
	if errObj := checkDeclaredLength(BuiltinNameHttpBuildRequest, headers, body); errObj != nil {
		return resultAndError(nil, errObj)
	}
	hasHost := false
	hasContentLength := false
	for _, h := range headers {
		if strings.EqualFold(h.key, "Host") {
			hasHost = true
		}
		if strings.EqualFold(h.key, "Content-Length") {
			hasContentLength = true
		}
	}
	if !hasHost && host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteString("\r\n")
	}
	writeHeaderLines(&b, headers)
	// A request carrying a body needs a Content-Length so the receiver knows
	// where it ends; add one when the caller didn't (matches http_build_response).
	if !hasContentLength && body != "" {
		b.WriteString("Content-Length: ")
		b.WriteString(strconv.Itoa(len(body)))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	return resultAndError(stringObj(b.String()), nil)
}

// HTTPBuildResponse serialises a response hash back into wire bytes.
// http_build_response(response HASH) -> STRING
// Fields: status (default 200), status_text, proto (default HTTP/1.1),
// headers (HASH), body (STRING). A Content-Length header is added when absent.
func HTTPBuildResponse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	resp := args[0]
	if _, ok := resp.(*object.Hash); !ok {
		if _, ok := resp.(*object.Struct); !ok {
			return resultAndError(nil, newError("argument 1 to `http_build_response` must be HASH or STRUCT, got %s", resp.Type()))
		}
	}

	status := optInt(resp, "status", 200)
	statusText := optString(resp, "status_text", http.StatusText(int(status)))
	if statusText == "" {
		statusText = "OK"
	}
	proto := optString(resp, "proto", "HTTP/1.1")
	body := optString(resp, "body", "")

	var b strings.Builder
	b.WriteString(proto)
	b.WriteString(" ")
	b.WriteString(strconv.FormatInt(status, 10))
	b.WriteString(" ")
	b.WriteString(statusText)
	b.WriteString("\r\n")

	headers := headersToOrdered(resp)
	// A status with no body has no length to agree or disagree with, and must
	// not be given one. See responseBodyAllowed.
	if responseBodyAllowed(status) {
		if errObj := checkDeclaredLength(BuiltinNameHttpBuildResponse, headers, body); errObj != nil {
			return resultAndError(nil, errObj)
		}
	} else if body != "" {
		return resultAndError(nil, newError(
			"%s: a %d response carries no body, and this one holds %d bytes; "+
				"bytes after a bodyless status are read as the start of the next message",
			BuiltinNameHttpBuildResponse, status, len(body)))
	}
	hasContentLength := false
	for _, h := range headers {
		if strings.EqualFold(h.key, "Content-Length") {
			hasContentLength = true
		}
	}
	writeHeaderLines(&b, headers)
	if !hasContentLength && responseBodyAllowed(status) {
		b.WriteString("Content-Length: ")
		b.WriteString(strconv.Itoa(len(body)))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)

	return resultAndError(stringObj(b.String()), nil)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type orderedHeader struct {
	key   string
	value string
}

func connAndTimeout(opName string, args []object.Object) (*managedConn, int64, *object.Error) {
	if len(args) != 2 {
		return nil, 0, newError("wrong number of arguments. got=%d, want=2", len(args))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return nil, 0, newError("argument 1 to `%s` must be INTEGER, got %s", opName, args[0].Type())
	}
	timeoutMs, ok := args[1].(*object.Integer)
	if !ok {
		return nil, 0, newError("argument 2 to `%s` must be INTEGER, got %s", opName, args[1].Type())
	}
	mc, ok := lookupConn(handle.Value)
	if !ok {
		return nil, 0, newError("%s: unknown connection handle %d", opName, handle.Value)
	}
	return mc, timeoutMs.Value, nil
}

func applyReadDeadline(mc *managedConn, timeoutMs int64) {
	if timeoutMs > 0 {
		_ = mc.conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	} else {
		_ = mc.conn.SetReadDeadline(time.Time{})
	}
}

func requestToHash(opName string, req *http.Request) (object.Object, *object.Error) {
	// Refused ahead of the body read, and without closing the body: Close()
	// on a net/http body fully consumes what is left of it
	// (net/http/transfer.go:1003-1006 in go1.26.6), so closing here would
	// drain the body of a message just refused -- and against a peer that
	// declares a body and never sends it, that drain waits for the deadline.
	// The connection stays the script's to close, as it is on every other
	// error return in this file (M26-NET-028).
	if fieldErr := checkHTTPHeaderFields(req.Header); fieldErr != nil {
		return nil, newError("%s: %s", opName, fieldErr.Error())
	}

	// The cap plus one is what separates a body that fits from one that does
	// not. io.LimitReader returns EOF at its bound and io.ReadAll turns EOF
	// into nil, so reading at exactly maxHTTPBodyBytes gave back the first
	// 32 MiB of a larger body with no error and no flag, indistinguishable
	// from the whole of a smaller one (M26-NET-031). Asking for one more byte
	// makes the overflow observable, and then it is refused: see the cap's own
	// comment for why a refusal and not a flag.
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxHTTPBodyBytes+1))
	_ = req.Body.Close()
	if err != nil {
		return nil, newError("%s: reading body: %s", opName, err.Error())
	}
	if len(bodyBytes) > maxHTTPBodyBytes {
		return nil, newError("%s: body exceeds %d bytes", opName, maxHTTPBodyBytes)
	}

	host := req.Host
	query := ""
	fullURL := req.URL.String()
	path := req.URL.Path
	if req.URL != nil {
		query = req.URL.RawQuery
		if host == "" {
			host = req.URL.Host
		}
	}

	return makeHashObject(map[string]object.Object{
		"method":  stringObj(req.Method),
		"url":     stringObj(fullURL),
		"path":    stringObj(path),
		"host":    stringObj(host),
		"proto":   stringObj(req.Proto),
		"query":   stringObj(query),
		"headers": headerToHash(req.Header),
		"body":    stringObj(string(bodyBytes)),
	}), nil
}

func responseToHash(opName string, resp *http.Response) (object.Object, *object.Error) {
	// Ahead of the body read and without closing it, for the reason written
	// out in requestToHash above (M26-NET-028).
	if fieldErr := checkHTTPHeaderFields(resp.Header); fieldErr != nil {
		return nil, newError("%s: %s", opName, fieldErr.Error())
	}

	// The cap plus one, for the reason given in requestToHash.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, newError("%s: reading body: %s", opName, err.Error())
	}
	if len(bodyBytes) > maxHTTPBodyBytes {
		return nil, newError("%s: body exceeds %d bytes", opName, maxHTTPBodyBytes)
	}

	return makeHashObject(map[string]object.Object{
		"status":      intObj(int64(resp.StatusCode)),
		"status_text": stringObj(responseStatusText(resp)),
		"proto":       stringObj(resp.Proto),
		"headers":     headerToHash(resp.Header),
		"body":        stringObj(string(bodyBytes)),
	}), nil
}

// responseStatusText returns the reason phrase exactly as it arrived on the
// wire (which may be custom or non-standard — worth preserving for an
// inspection tool), falling back to the canonical text when the server sent an
// empty phrase.
func responseStatusText(resp *http.Response) string {
	if phrase := strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode))); phrase != "" {
		return phrase
	}
	return http.StatusText(resp.StatusCode)
}

// headerToHash turns a header block into a hash.
//
// A field that arrived on more than one line is combined into one
// comma-separated value, which RFC 9110 section 5.3 permits for any field whose
// value is defined as a comma-separated list -- and which it names exactly one
// exception to: Set-Cookie, which does not use list syntax and may not be
// folded. RFC 6265 section 3 says the same from the other side.
//
// Joining it was not a cosmetic loss. A cookie's Expires date carries a comma
// of its own ("Expires=Wed, 21 Oct 2026 07:28:00 GMT"), so two cookies joined
// with ", " cannot be split back apart by anything, and a response that arrived
// with two Set-Cookie lines was rebuilt with one holding both -- one malformed
// cookie where the server sent two, with the second silently gone. For an
// interception proxy that is a session the client never receives; for a
// recorded response it is evidence that says the server sent something it did
// not.
//
// So Set-Cookie is a list here, one element per line, and it is a list whether
// there is one cookie or five: a field whose type depended on how many values
// happened to arrive would need every script to handle both. Every other field
// stays a string, so nothing that reads headers["Content-Type"] changes.
func headerToHash(header http.Header) *object.Hash {
	pairs := make(map[string]object.Object, len(header))
	for k, vals := range header {
		if headerMustNotBeCombined(k) {
			// stringListObj and not stringArrayObj: cookie order is meaning.
			// Two Set-Cookie lines naming the same cookie leave the last one
			// standing, so sorting them could change which.
			pairs[k] = stringListObj(vals)
			continue
		}
		pairs[k] = stringObj(strings.Join(vals, ", "))
	}
	return makeHashObject(pairs)
}

// headerMustNotBeCombined reports whether a field's lines have to stay apart.
//
// One field, and it is named rather than guessed at: RFC 9110 section 5.3 gives
// the rule and the sole exception to it. The name is canonicalised first,
// because a peer may have spelled it "set-cookie" and http.Header's own keys
// are canonical.
func headerMustNotBeCombined(name string) bool {
	return textproto.CanonicalMIMEHeaderKey(name) == "Set-Cookie"
}

// headersToOrdered extracts a deterministic, sorted header list from a request
// or response hash so serialisation is reproducible.
//
// An entry holding a list stands for one field line per element, which is how a
// Set-Cookie that arrived on two lines goes back out on two -- see
// headerToHash for why that field cannot be folded into one.
func headersToOrdered(obj object.Object) []orderedHeader {
	val, ok := objField(obj, "headers")
	if !ok {
		return nil
	}

	out := []orderedHeader{}
	switch h := val.(type) {
	case *object.Hash:
		for _, pair := range h.Pairs {
			key, ok := pair.Key.(*object.String)
			if !ok {
				continue
			}
			out = append(out, orderedHeaderLines(key.Value, pair.Value)...)
		}
	case *object.Struct:
		for k, v := range h.Fields {
			out = append(out, orderedHeaderLines(k, v)...)
		}
	}

	// SliceStable, not Slice. Two lines of the same field sort equal, and an
	// unstable sort is free to swap them -- which for Set-Cookie decides which
	// of two cookies of the same name the client keeps.
	sort.SliceStable(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// orderedHeaderLines turns one hash entry into the field lines it stands for.
func orderedHeaderLines(key string, value object.Object) []orderedHeader {
	arr, ok := value.(*object.Array)
	if !ok {
		return []orderedHeader{{key: key, value: headerValueString(value)}}
	}
	out := make([]orderedHeader, 0, len(arr.Elements))
	for _, element := range arr.Elements {
		out = append(out, orderedHeader{key: key, value: headerValueString(element)})
	}
	return out
}

// responseBodyAllowed reports whether a response with this status may carry a
// body at all.
//
// The three cases are RFC 9110's and net/http's alike: every 1xx, a 204 and a
// 304. For those, Content-Length is not a statement about this message's body
// and the two cannot be compared -- a 304's Content-Length describes the cached
// representation the recipient already holds, which an interception proxy never
// sees, so it parses to an empty body with the header intact and that is
// correct. RFC 9110 section 8.6 also forbids sending Content-Length at all in a
// 1xx or a 204, which is why nothing is added for these either.
func responseBodyAllowed(status int64) bool {
	return status >= 200 && status != 204 && status != 304
}

// checkDeclaredLength refuses a Content-Length that disagrees with the body it
// is about.
//
// http_build_request and http_build_response write the caller's headers out as
// they are and add a Content-Length only when none is there, which meant the
// one thing these builtins exist for broke them: parse a message, change the
// body, rebuild it. The parsed hash carries the original Content-Length, so a
// body of any other length produced a message declaring the old one -- a 12-byte
// body under "Content-Length: 5". A receiver believes the header, so the next
// hop reads five bytes of this message and then starts parsing the remaining
// seven as the beginning of another one. That is a desynchronised connection,
// and it is the kind that request smuggling is built out of (M26-NET-016).
//
// It refuses rather than quietly rewriting the number. The header is the
// caller's explicit instruction about this message and silently replacing it
// would be a different answer than the one asked for; the refusal says what to
// do instead, and dropping the header is a one-line change that gets a correct
// length computed. A deliberately inconsistent message -- which is a real thing
// to want to send, for smuggling research against a host under test -- is
// written with net_conn_write and a string, which these builtins are not in the
// way of.
func checkDeclaredLength(opName string, headers []orderedHeader, body string) *object.Error {
	seen := false
	for _, h := range headers {
		if !strings.EqualFold(h.key, "Content-Length") {
			continue
		}
		if seen {
			return newError("%s: two Content-Length headers; a message declares its length once", opName)
		}
		seen = true
		declared, err := strconv.Atoi(strings.TrimSpace(h.value))
		if err != nil {
			return newError("%s: Content-Length %q is not a number", opName, h.value)
		}
		if declared != len(body) {
			return newError(
				"%s: Content-Length declares %d bytes and the body holds %d; "+
					"drop the header and a correct one is written for you",
				opName, declared, len(body))
		}
	}
	return nil
}

func headerValueString(v object.Object) string {
	if s, ok := v.(*object.String); ok {
		return s.Value
	}
	return v.Inspect()
}

func writeHeaderLines(b *strings.Builder, headers []orderedHeader) {
	for _, h := range headers {
		b.WriteString(h.key)
		b.WriteString(": ")
		b.WriteString(h.value)
		b.WriteString("\r\n")
	}
}
