package builtin

import (
	"fmt"
	"net/http"
)

// maxHTTPHeaderFields bounds how many header fields one HTTP message head may
// carry. The cost of a field is not its length: each one becomes an entry in an
// http.Header and then a pair in the hash a builtin hands back, which is held
// as a VM variable and re-encrypted on every store, so a field spelled in five
// bytes costs far more than five bytes and a bound counted in bytes does not
// see it. Measured with a 1 MiB head bound in place, 87,964 one-line fields
// fitted in 1,044,485 bytes on the wire and grew the heap by 33,246,576 --
// 31.8 times what arrived (M26-NET-028). 100 is Apache httpd's
// LimitRequestFields default and Tomcat's maxHeaderCount default; net/http has
// no field count of its own to inherit, only byte bounds.
//
//mutant:limit count
const maxHTTPHeaderFields = 100

// httpHeaderFieldCount is how many header lines arrived, which is not how many
// distinct names did.
//
// http.Header is a map[string][]string and collapses repeats of one name into a
// single entry holding a slice, so len(header) is the number of names: a head
// spelling one name 90,000 times is one name and 90,000 fields, and the hash
// builders then join all 90,000 values into one string -- the same
// amplification in a different shape. Summing the slices counts the lines that
// arrived, which is also what net/textproto's own maxHeaders argument counts
// (net/textproto/reader.go:568 in go1.26.6), so the figure means here what it
// means in a server's configuration.
func httpHeaderFieldCount(header http.Header) int {
	fields := 0
	for _, values := range header {
		fields += len(values)
	}
	return fields
}

// checkHTTPHeaderFields refuses a head carrying more fields than
// maxHTTPHeaderFields allows, and says how many arrived as well as how many are
// allowed: the difference between 101 and 90,000 is the difference between a
// verbose client and an attack, and an examiner reading "more than the 100
// allowed" cannot tell them apart.
//
// It refuses rather than trimming. A hash holding the first hundred fields of a
// larger head is a wrong answer with nothing in it to say so.
//
// The count is taken after the parse because neither entry point this package
// uses can be told to stop earlier: http.ReadRequest and http.ReadResponse both
// reach textproto.Reader.ReadMIMEHeader, which passes math.MaxInt64 for the
// field budget as well as for the memory one (net/textproto/reader.go:508 in
// go1.26.6), and neither takes a count to pass instead. So the transient
// http.Header is built either way and stays bounded only by whatever bounds the
// head in bytes. What refusing here removes is the hash that outlives the call
// -- the VM variable, re-encrypted on every store -- and the body read, which
// every caller does after this check rather than before it.
//
// A request's Host field is not among the fields counted, because net/http
// moves it to Request.Host and deletes it from Request.Header
// (net/http/request.go:1064 in go1.26.6), so it never reaches the hash this
// bound protects.
func checkHTTPHeaderFields(header http.Header) error {
	fields := httpHeaderFieldCount(header)
	if fields > maxHTTPHeaderFields {
		return fmt.Errorf("the message head carries %d header fields; this build accepts %d",
			fields, maxHTTPHeaderFields)
	}
	return nil
}
