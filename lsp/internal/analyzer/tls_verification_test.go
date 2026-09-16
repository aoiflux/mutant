package analyzer

import (
	"strings"
	"testing"
)

// tlsMessages returns the messages of every tlsVerificationDisabled diagnostic
// in src. Both of its messages name the builtin and then say either
// "certificate verification" or "allows TLS".
func tlsMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source == nil || *d.Source != "mutant-lint" {
			continue
		}
		if strings.Contains(d.Message, "certificate verification") || strings.Contains(d.Message, "allows TLS") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestTlsVerificationDisabledFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"verification switched off inline",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"insecure": true});`,
			"skip certificate verification",
		},
		{
			// The idiom the corpus itself uses: the options are bound to a
			// name and the call takes the name.
			"verification switched off through a name",
			`let opts = {"server_name": "example.com", "insecure": true};
let conn, err = net_tls_connect("example.com:443", 5000, opts);`,
			"skip certificate verification",
		},
		{
			"verification switched off on an upgrade",
			`let up, err = net_tls_upgrade_client(handle, {"insecure": true});`,
			"skip certificate verification",
		},
		{
			"a struct literal rather than a hash",
			`let conn, err = net_tls_connect("example.com:443", 5000, TlsOptions{insecure: true});`,
			"skip certificate verification",
		},
		{
			"a client floor of TLS 1.0",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"min_version": "1.0"});`,
			"allows TLS 1.0",
		},
		{
			"a client floor of TLS 1.1 in the alternate spelling",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"min_version": "TLS1_1"});`,
			"allows TLS 1.1",
		},
		{
			// A server accepting 1.0 is the same finding from the other side,
			// and applyServerTLSOptions reads the same key.
			"a server floor of TLS 1.0",
			`let l, err = net_tls_listen("0.0.0.0:8443", cert, key, {"min_version": "1.0"});`,
			"allows TLS 1.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := tlsMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

func TestTlsVerificationDisabledStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// The corpus's own secure_client.mut.
			"a 1.2 floor with a server name",
			`let tls_opts = {"server_name": "example.com", "min_version": "1.2"};
let conn, err = net_tls_connect("example.com:443", 5000, tls_opts);`,
		},
		{
			"no options at all",
			`let conn, err = net_tls_connect("example.com:443", 5000);`,
		},
		{
			"verification explicitly left on",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"insecure": false});`,
		},
		{
			// Whether this is true at run time is not knowable here, and
			// guessing is how a security rule becomes something people
			// switch off.
			"a computed insecure flag",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"insecure": debug_mode});`,
		},
		{
			"a computed min_version",
			`let conn, err = net_tls_connect("example.com:443", 5000, {"min_version": floor});`,
		},
		{
			// Two bindings mean the name has no single value, so the options
			// cannot be followed.
			"options rebound before the call",
			`let opts = {"insecure": true};
let opts = {"min_version": "1.2"};
let conn, err = net_tls_connect("example.com:443", 5000, opts);`,
		},
		{
			// `insecure` is not read on the server side, so saying anything
			// about it would be saying something untrue.
			"an insecure key on a listener",
			`let l, err = net_tls_listen("0.0.0.0:8443", cert, key, {"insecure": true});`,
		},
		{
			"a plain hash that is not TLS options",
			`let settings = {"insecure": true, "min_version": "1.0"};
putln(settings);`,
		},
		{
			// The name is bound in this file, so it is not the builtin.
			"a shadowed builtin",
			`let net_tls_connect = fn(a, b, c) { return c; };
let conn = net_tls_connect("example.com:443", 5000, {"insecure": true});`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := tlsMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

// A call can be wrong in both ways at once, and each is its own fix.
func TestTlsVerificationDisabledReportsBothOptions(t *testing.T) {
	src := `let conn, err = net_tls_connect("h:443", 5000, {"insecure": true, "min_version": "1.0"});`
	if messages := tlsMessages(t, src); len(messages) != 2 {
		t.Fatalf("want two reports, got %d: %v", len(messages), messages)
	}
}

func TestTlsVerificationDisabledCanBeTurnedOff(t *testing.T) {
	src := `let conn, err = net_tls_connect("h:443", 5000, {"insecure": true});`

	config := DefaultLintConfig()
	config.TlsVerificationDisabled = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "certificate verification") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
