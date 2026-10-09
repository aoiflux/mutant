package builtin

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"mutant/object"
)

// httpRequestTimeout bounds one request an http_* builtin or lua_run_http
// makes, from dialling to the last byte of the body.
//
//mutant:limit duration
const httpRequestTimeout = 30 * time.Second

// httpTLSHandshakeTimeout, httpIdleConnTimeout and httpMaxIdleConns are what
// net/http's default transport sets. The http_* builtins no longer send
// through that transport, so they name the values it would have given them.
const (
	// httpTLSHandshakeTimeout bounds the TLS handshake of one connection.
	//
	//mutant:limit duration
	httpTLSHandshakeTimeout = 10 * time.Second

	// httpIdleConnTimeout is how long a connection kept for reuse waits for
	// the next request before it is closed.
	//
	//mutant:limit duration
	httpIdleConnTimeout = 90 * time.Second

	// httpMaxIdleConns is how many connections, across every host, are kept
	// for reuse.
	//
	//mutant:limit count
	httpMaxIdleConns = 100
)

// httpMaxRedirects bounds how many redirects one http_get, http_post or
// http_request follows. It is ten, which is what net/http's own
// defaultCheckRedirect stops after -- and that default is one in the strict
// sense, because a CheckRedirect of our own replaces it outright rather than
// adding to it. So the number has to be named here: checkHTTPRedirect
// exists to refuse a hop that leaves TLS, and adding it without a count would
// have made the chain unbounded instead, so a server that redirects to itself
// forever would have been followed until the request timeout -- and the limit
// scanner would not have seen a thing, because the number it used to be was in
// someone else's package.
//
//mutant:limit count
const httpMaxRedirects = 10

// httpClient is the client the http_* builtins and lua_run_http send with. Its
// transport names no proxy: net/http's default transport takes one from
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY, so whoever set the examiner's
// environment saw every request and could rewrite a plain-HTTP answer
// (M26-NET-010). It trusts clientRootCAs, which on Linux is not whatever
// SSL_CERT_FILE and SSL_CERT_DIR name. It is built on first use, because
// reading the certificate store costs something a program that never fetches
// should not pay.
var httpClient = sync.OnceValues(func() (*http.Client, error) {
	roots, err := clientRootCAs()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:       httpRequestTimeout,
		CheckRedirect: checkHTTPRedirect,
		Transport: &http.Transport{
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: roots},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: httpTLSHandshakeTimeout,
			IdleConnTimeout:     httpIdleConnTimeout,
			MaxIdleConns:        httpMaxIdleConns,
		},
	}, nil
})

// checkHTTPRedirect decides whether one redirect is followed.
//
// It refuses a hop that leaves TLS. An https URL is the examiner's instruction
// to fetch over a channel nobody on the path can read or rewrite, and a 302 to
// an http URL discards that instruction -- quietly, because the result reported
// the status and body of the final hop and named no URL at all (M26-NET-015).
// Whoever can answer the plaintext request can choose what the examiner sees,
// which is the same exposure M26-NET-010 closed by refusing the proxy variables.
// net/http treats that one transition as a leak too -- refererForURL withholds
// the Referer on https to http and on no other hop, citing RFC 7231 section
// 5.5.2 for it (refererForURL, net/http/client.go:147-154 in go1.26.6) -- it
// just follows the hop anyway. The other direction, http to
// https, is an upgrade and is followed.
//
// A cross-host hop is NOT refused. Redirecting to a CDN or to a regional host
// is how most of the web serves a file, so refusing it would break ordinary
// fetches, and the row's own first proposal -- record where the answer came
// from -- is what makes such a hop reportable instead of invisible. The final
// URL, the final method and the hop count all travel in the result now.
func checkHTTPRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= httpMaxRedirects {
		return fmt.Errorf("stopped after %d redirects", httpMaxRedirects)
	}
	previous := via[len(via)-1]
	if previous.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf(
			"refusing a redirect out of TLS: %s redirected to %s, which is not https; "+
				"fetch that URL directly if the plaintext answer is what you want",
			previous.URL.Redacted(), req.URL.Redacted())
	}
	return nil
}

func HttpGet(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	url, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument to `http_get` must be STRING, got %s", args[0].Type()))
	}
	client, err := httpClient()
	if err != nil {
		return httpResponseOrError2(nil, err, BuiltinNameHttpGet)
	}
	resp, err := client.Get(url.Value)
	return httpResponseOrError2(resp, err, BuiltinNameHttpGet)
}

func HttpPost(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	url, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_post` must be STRING, got %s", args[0].Type()))
	}
	if errObj := refuseClassified(BuiltinNameHttpPost, args...); errObj != nil {
		return resultAndError(nil, errObj)
	}
	body, errObj := httpBodyString(args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	contentType := "application/octet-stream"
	if len(args) == 3 {
		ctObj, ok := args[2].(*object.String)
		if !ok {
			return resultAndError(nil, newError("argument 3 to `http_post` must be STRING, got %s", args[2].Type()))
		}
		contentType = ctObj.Value
	}
	client, err := httpClient()
	if err != nil {
		return httpResponseOrError2(nil, err, BuiltinNameHttpPost)
	}
	resp, err := client.Post(url.Value, contentType, strings.NewReader(body))
	return httpResponseOrError2(resp, err, BuiltinNameHttpPost)
}

func HttpRequest(args ...object.Object) object.Object {
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	method, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `http_request` must be STRING, got %s", args[0].Type()))
	}
	url, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `http_request` must be STRING, got %s", args[1].Type()))
	}
	if errObj := refuseClassified(BuiltinNameHttpRequest, args...); errObj != nil {
		return resultAndError(nil, errObj)
	}
	body, errObj := httpBodyString(args[2])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	headers, errObj := httpHeaderMap(args[3])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	req, err := http.NewRequest(strings.ToUpper(method.Value), url.Value, strings.NewReader(body))
	if err != nil {
		return resultAndError(nil, newError("http_request: %s", err.Error()))
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client, err := httpClient()
	if err != nil {
		return httpResponseOrError2(nil, err, BuiltinNameHttpRequest)
	}
	resp, err := client.Do(req)
	return httpResponseOrError2(resp, err, BuiltinNameHttpRequest)
}

func httpHeaderMap(obj object.Object) (map[string]string, *object.Error) {
	switch v := obj.(type) {
	case *object.Hash:
		result := make(map[string]string, len(v.Pairs))
		for _, pair := range v.Pairs {
			keyObj, ok := pair.Key.(*object.String)
			if !ok {
				return nil, newError("argument 4 to `http_request` must have STRING header keys, got %s", pair.Key.Type())
			}
			result[keyObj.Value] = pair.Value.Inspect()
		}
		return result, nil
	case *object.Struct:
		result := make(map[string]string, len(v.Fields))
		for k, val := range v.Fields {
			result[k] = val.Inspect()
		}
		return result, nil
	default:
		return nil, newError("argument 4 to `http_request` must be HASH or STRUCT, got %s", obj.Type())
	}
}

func httpBodyString(obj object.Object) (string, *object.Error) {
	switch v := obj.(type) {
	case *object.String:
		return v.Value, nil
	case *object.Hash, *object.Struct:
		payload, err := httpJSONBody(obj)
		if err != nil {
			return "", newError("argument body could not be converted to JSON: %s", err.Error())
		}
		return payload, nil
	default:
		return "", newError("argument body must be STRING, HASH, or STRUCT, got %s", obj.Type())
	}
}

func httpJSONBody(obj object.Object) (string, error) {
	value, err := objectToGoValue(obj)
	if err != nil {
		return "", err
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func objectToGoValue(obj object.Object) (any, error) {
	switch v := obj.(type) {
	case *object.String:
		return v.Value, nil
	case *object.Integer:
		return v.Value, nil
	case *object.Float:
		return v.Value, nil
	case *object.Boolean:
		return v.Value, nil
	case *object.Null:
		return nil, nil
	case *object.Array:
		arr := make([]any, 0, len(v.Elements))
		for _, el := range v.Elements {
			goVal, err := objectToGoValue(el)
			if err != nil {
				return nil, err
			}
			arr = append(arr, goVal)
		}
		return arr, nil
	case *object.Hash:
		m := make(map[string]any, len(v.Pairs))
		for _, pair := range v.Pairs {
			k, ok := pair.Key.(*object.String)
			if !ok {
				return nil, fmt.Errorf("JSON object keys must be STRING, got %s", pair.Key.Type())
			}
			goVal, err := objectToGoValue(pair.Value)
			if err != nil {
				return nil, err
			}
			m[k.Value] = goVal
		}
		return m, nil
	case *object.Struct:
		m := make(map[string]any, len(v.Fields))
		for k, field := range v.Fields {
			goVal, err := objectToGoValue(field)
			if err != nil {
				return nil, err
			}
			m[k] = goVal
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported body field type for JSON: %s", obj.Type())
	}
}

func httpResponseOrError(resp *http.Response, err error) object.Object {
	if err != nil {
		return httpErrorResult(err)
	}
	defer resp.Body.Close()

	// A response head past the cap is refused before the io.ReadAll below,
	// which has no size bound of its own (M26-NET-021), and before the
	// headers hash is built. The deferred Close above still runs, so the body
	// is still drained for connection reuse: what this saves is the unbounded
	// read into memory and the hash that outlives the call, not the bytes on
	// the wire.
	//
	// This family's head budget is not the interception builtins': httpClient's
	// transport sets no MaxResponseHeaderBytes, so net/http's default of 10
	// MiB applies (net/http/transport.go:333 in go1.26.6), which is ten times
	// the head and so ten times the field count (M26-NET-032).
	if err := checkHTTPHeaderFields(resp.Header); err != nil {
		return httpErrorResult(err)
	}

	// io.ReadAll stops at the first error, so rawBody holds whatever arrived
	// before the stream broke. Those bytes are kept, and the reason travels
	// with them in the error field: readErr used to be read once here and never
	// looked at again while the error field below was a hard-coded "", so a
	// response cut off mid-body arrived as a successful response with an empty
	// body -- real status, real headers, no error anywhere (M26-NET-002).
	//
	// httpResponseOrError2 decides whether to return a Go-level error by reading
	// that field, so setting it is what makes http_get, http_post and
	// http_request all report this.
	//
	// The status line and the headers did arrive and are not in doubt, so they
	// are reported as they always were. That is also what lets a caller tell a
	// truncated response, which carries a real status, from a connection that
	// never produced one, which httpErrorResult reports with status 0.
	//
	// The read is bounded by the cap plus one byte, which is what separates a
	// body that fits from one that does not: io.LimitReader returns EOF at its
	// bound and io.ReadAll turns EOF into nil, so reading at exactly the cap
	// would hand back the first 32 MiB of a larger body with no error and no
	// flag. This read had no bound at all, so a 48 MiB answer -- or an endless
	// one, until the 30 s timeout -- was buffered whole and then copied again
	// into a string, while the interception builtins in this same package
	// refused at the same figure (M26-NET-021). It is maxHTTPBodyBytes and not
	// a second number, because one number is easier to answer for than two.
	//
	// Over the cap the bytes are dropped rather than returned short. A body cut
	// at the cap is not "what arrived before the stream broke" -- it is a whole
	// answer cut at an arbitrary boundary, and a script that read the error
	// field second would have parsed 32 MiB of a 48 MiB feed as the feed.
	rawBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	errText := ""
	switch {
	case readErr != nil:
		errText = "reading body: " + readErr.Error()
	case len(rawBody) > maxHTTPBodyBytes:
		errText = fmt.Sprintf("body exceeds %d bytes", maxHTTPBodyBytes)
		rawBody = nil
	}

	finalURL, finalMethod, redirects := responseProvenance(resp)

	return makeHashObject(map[string]object.Object{
		"status": intObj(int64(resp.StatusCode)),
		"body":   stringObj(string(rawBody)),
		// headerToHash, the same reading the interception builtins use, so a
		// Set-Cookie sent on two lines arrives as two here as well.
		"headers": headerToHash(resp.Header),
		"error":   stringObj(errText),
		// Where the answer actually came from. The client follows redirects,
		// including to another host, and a result holding only a status and a
		// body said nothing about having done so: an indicator feed answered by
		// a parked domain or a captive portal read as the answer for the URL
		// asked (M26-NET-015). final_url is the URL that produced this status
		// and this body; redirects is how many hops it took, 0 for none; and
		// final_method is the method that URL was asked with, which is not
		// always the one the script named -- net/http turns a POST into a GET
		// on a 301, 302 or 303, as the RFC and every browser do.
		"final_url":    stringObj(finalURL),
		"final_method": stringObj(finalMethod),
		"redirects":    intObj(int64(redirects)),
	})
}

// responseProvenance reports which URL answered, with which method, and how
// many redirects it took to get there.
//
// resp.Request is the request that produced this response -- the last one,
// after every hop -- and its Response field is the redirect that sent it there,
// so the chain walks backwards to the request the script made. net/http keeps
// both links for exactly this purpose: Response.Request is "the request that
// was sent to obtain this Response" (net/http/response.go:112-115) and
// Request.Response is "the redirect response which caused this request to be
// created", populated only during client redirects (net/http/request.go:320-323).
//
// The walk is bounded even though checkHTTPRedirect already bounds the chain:
// this reads a linked list out of another package's structure, and a loop here
// would hang the call rather than return a wrong number.
func responseProvenance(resp *http.Response) (finalURL, finalMethod string, redirects int) {
	req := resp.Request
	if req == nil {
		return "", "", 0
	}
	finalMethod = req.Method
	if req.URL != nil {
		finalURL = req.URL.String()
	}
	for r := req; r != nil && r.Response != nil && redirects <= httpMaxRedirects; r = r.Response.Request {
		redirects++
	}
	return finalURL, finalMethod, redirects
}

func httpErrorResult(err error) object.Object {
	return makeHashObject(map[string]object.Object{
		"status":  intObj(0),
		"body":    stringObj(""),
		"headers": makeHashObject(map[string]object.Object{}),
		"error":   stringObj(err.Error()),
	})
}

func httpResponseOrError2(resp *http.Response, err error, opName string) object.Object {
	if err != nil {
		return resultAndError(httpErrorResult(err), newError("%s: %s", opName, err.Error()))
	}

	result := httpResponseOrError(resp, nil)
	hash, ok := result.(*object.Hash)
	if !ok {
		return resultAndError(result, nil)
	}

	errValueObj, ok := hashValueByStringKey(hash, "error")
	if !ok {
		return resultAndError(hash, nil)
	}
	errStr, ok := errValueObj.(*object.String)
	if !ok || errStr.Value == "" {
		return resultAndError(hash, nil)
	}

	return resultAndError(hash, newError("%s: %s", opName, errStr.Value))
}

func hashValueByStringKey(hash *object.Hash, key string) (object.Object, bool) {
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		return nil, false
	}
	return pair.Value, true
}
