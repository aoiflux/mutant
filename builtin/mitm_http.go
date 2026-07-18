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
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

const maxHTTPBodyBytes = 32 << 20 // 32 MiB cap so a hostile stream can't OOM us.

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
	return resultAndError(requestToHash("http_parse_request", req))
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
	return resultAndError(responseToHash("http_parse_response", resp))
}

// HTTPConnReadRequest reads exactly one HTTP request from a connection handle,
// honouring Content-Length / chunked framing.
// http_conn_read_request(handle INTEGER, timeout_ms INTEGER) -> HASH
func HTTPConnReadRequest(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout("http_conn_read_request", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	req, err := http.ReadRequest(mc.buffered())
	if err != nil {
		return resultAndError(nil, newError("http_conn_read_request: %s", err.Error()))
	}
	return resultAndError(requestToHash("http_conn_read_request", req))
}

// HTTPConnReadResponse reads exactly one HTTP response from a connection handle.
// http_conn_read_response(handle INTEGER, timeout_ms INTEGER) -> HASH
func HTTPConnReadResponse(args ...object.Object) object.Object {
	mc, timeoutMs, errObj := connAndTimeout("http_conn_read_response", args)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	applyReadDeadline(mc, timeoutMs)
	resp, err := http.ReadResponse(mc.buffered(), nil)
	if err != nil {
		return resultAndError(nil, newError("http_conn_read_response: %s", err.Error()))
	}
	return resultAndError(responseToHash("http_conn_read_response", resp))
}

// HTTPBuildRequest serialises a request hash back into wire bytes.
// http_build_request(request HASH) -> STRING
// Fields: method (default GET), url or path (default "/"), host, proto
// (default HTTP/1.1), headers (HASH), body (STRING).
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
	hasHost := false
	for _, h := range headers {
		if strings.EqualFold(h.key, "Host") {
			hasHost = true
		}
	}
	if !hasHost && host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteString("\r\n")
	}
	writeHeaderLines(&b, headers)
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
	hasContentLength := false
	for _, h := range headers {
		if strings.EqualFold(h.key, "Content-Length") {
			hasContentLength = true
		}
	}
	writeHeaderLines(&b, headers)
	if !hasContentLength {
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
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxHTTPBodyBytes))
	_ = req.Body.Close()
	if err != nil {
		return nil, newError("%s: reading body: %s", opName, err.Error())
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
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes))
	_ = resp.Body.Close()
	if err != nil {
		return nil, newError("%s: reading body: %s", opName, err.Error())
	}

	return makeHashObject(map[string]object.Object{
		"status":      intObj(int64(resp.StatusCode)),
		"status_text": stringObj(http.StatusText(resp.StatusCode)),
		"proto":       stringObj(resp.Proto),
		"headers":     headerToHash(resp.Header),
		"body":        stringObj(string(bodyBytes)),
	}), nil
}

func headerToHash(header http.Header) *object.Hash {
	pairs := make(map[string]object.Object, len(header))
	for k, vals := range header {
		pairs[k] = stringObj(strings.Join(vals, ", "))
	}
	return makeHashObject(pairs)
}

// headersToOrdered extracts a deterministic, sorted header list from a request
// or response hash so serialisation is reproducible.
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
			out = append(out, orderedHeader{key: key.Value, value: headerValueString(pair.Value)})
		}
	case *object.Struct:
		for k, v := range h.Fields {
			out = append(out, orderedHeader{key: k, value: headerValueString(v)})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
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
