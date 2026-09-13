package analyzer

import (
	"strings"
	"testing"
)

// secretMessages returns the messages of every hardcodedSecret diagnostic in
// src. Both of its messages say "credential in source".
func secretMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source != nil && *d.Source == "mutant-lint" && strings.Contains(d.Message, "credential in source") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestHardcodedSecretFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a password under a name that says so",
			`let db_password = "Tr0ub4dor&3-x91";`,
			"`db_password` holds what looks like a credential",
		},
		{
			"an API key in a hash",
			`let config = {"api_key": "b7Xq2mR9tLp4Ks8W"};`,
			"`api_key` holds",
		},
		{
			"a client secret in a struct",
			`let c = Client{client_secret: "9f3a-22bd-4e71-a0c8"};`,
			"`client_secret` holds",
		},
		{
			// A provider's own prefix is evidence on its own, with no help
			// from the name beside it.
			"an AWS access key with no name signal at all",
			`let k = "AKIAIOSFODNN7EXAMPLE";`,
			"an AWS access key ID",
		},
		{
			"a GitHub token in an argument",
			`let r, err = http_get(url, {"Authorization": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"});`,
			"a GitHub token",
		},
		{
			"a private key",
			`let key = "-----BEGIN RSA PRIVATE KEY-----MIIEow==";`,
			"a private key",
		},
		{
			// Not decoded anywhere, so it is being presented rather than
			// examined.
			"a signed JWT that is only ever sent",
			`let bearer = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
let r, err = http_get(url, {"Authorization": bearer});`,
			"a signed JWT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := secretMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

// These are the cases that decided the rule's shape. The first three are
// literally what the corpus contains.
func TestHardcodedSecretStaysQuietOnTheCorpusShapes(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// examples/workshop/jwt_inspect.mut -- a sample token whose entire
			// purpose is to be taken apart.
			"a JWT assembled from pieces and then decoded",
			`let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
  "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ" +
  "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
let jwt, err = jwt_decode(token);`,
		},
		{
			// examples/network/http_example.mut
			"a bearer placeholder in a header",
			`let headers = {"Authorization": "Bearer my-token", "X-Custom": "mutant"};`,
		},
		{
			// examples/crypto/crypto_toolkit.mut -- an argument carries no name
			// signal, which is the line that leaves this alone without a
			// special case for it.
			"a key literal in an argument position",
			`putln(hmac("secret-key", msg, "sha256"));`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := secretMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

func TestHardcodedSecretStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// A name signal beside a word is a label, not a leak.
			"a word under a secret-shaped name",
			`let password_field = "password";`,
		},
		{
			"a placeholder",
			`let api_key = "your-api-key-here";`,
		},
		{
			"a redaction",
			`let token = "xxxxxxxxxxxx";`,
		},
		{
			"an empty value",
			`let secret = "";`,
		},
		{
			"too short to have been issued",
			`let token = "abc123";`,
		},
		{
			"a sentence rather than a credential",
			`let password_hint = "the one from the wiki";`,
		},
		{
			"a value read at run time",
			`let api_key, err = fs_read("key.txt");`,
		},
		{
			// tokenize and authority are not names about secrets.
			"a name that merely contains the letters",
			`let tokenizer_pattern = "a-z0-9_+";`,
		},
		{
			"a base64 sample being decoded",
			`let secret_blob = "U29tZUJhc2U2NEVuY29kZWRTdHJpbmc=";
let raw, err = base64_decode(secret_blob);`,
		},
		{
			"a certificate being parsed",
			`let private_key = "-----BEGIN RSA PRIVATE KEY-----MIIEow==";
let parsed, err = pem_decode(private_key);`,
		},
		{
			"an unrelated literal",
			`let greeting = "hello there";`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := secretMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

func TestHardcodedSecretCanBeTurnedOff(t *testing.T) {
	src := `let db_password = "Tr0ub4dor&3-x91";`

	config := DefaultLintConfig()
	config.HardcodedSecret = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "credential in source") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
