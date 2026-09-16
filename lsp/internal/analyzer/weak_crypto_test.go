package analyzer

import (
	"strings"
	"testing"
)

// weakCryptoMessages returns the messages of every weakCrypto diagnostic in
// src. Its two messages say "authenticity check" and "asked for".
func weakCryptoMessages(t *testing.T, src string) []string {
	t.Helper()

	snapshot := New().Analyze(src)
	out := make([]string, 0, 2)
	for _, d := range Diagnostics(snapshot, DefaultLintConfig()) {
		if d.Source == nil || *d.Source != "mutant-lint" {
			continue
		}
		if strings.Contains(d.Message, "authenticity check") || strings.Contains(d.Message, "is asked for") {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestWeakCryptoFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			"a digest checked against one written into the program",
			`let ok = hash_md5(payload) == "5d41402abc4b2a76b9719d911017c592";`,
			"`hash_md5` decides whether this matches a digest written into the program",
		},
		{
			"the expected digest on the left",
			`let ok = "5d41402abc4b2a76b9719d911017c592" == hash_md5(payload);`,
			"`hash_md5` decides",
		},
		{
			"a digest bound to a name first",
			`let digest = hash_sha1(payload);
if (digest == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") { putln("ok"); };`,
			"`hash_sha1` decides",
		},
		{
			"an inequality is the same decision",
			`if (hash_sha1(payload) != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d") { putln("tampered"); };`,
			"`hash_sha1` decides",
		},
		{
			"a checksum standing in for a hash",
			`let ok = hash_crc32(payload) == "414fa339";`,
			"never a hash",
		},
		{
			// Keying a hash has exactly one purpose, so the algorithm settles
			// it with no context at all.
			"an HMAC over MD5",
			`let mac = hmac(key, message, "md5");`,
			"`hmac` is asked for MD5",
		},
		{
			"an HMAC over SHA-1 through a name",
			`let algo = "sha1";
let mac = hmac(key, message, algo);`,
			"`hmac` is asked for SHA-1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messages := weakCryptoMessages(t, tc.src)
			if len(messages) != 1 {
				t.Fatalf("want exactly one report, got %d: %v", len(messages), messages)
			}
			if !strings.Contains(messages[0], tc.want) {
				t.Fatalf("message %q does not contain %q", messages[0], tc.want)
			}
		})
	}
}

// The silences matter more than the reports here. MD5 is daily work in a
// forensic language, and a rule that reported it would be switched off within
// the hour.
func TestWeakCryptoStaysQuiet(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			"two artifacts compared with each other",
			`let same = hash_md5(a) == hash_md5(b);`,
		},
		{
			"a digest looked up in a known-file set",
			`let known, err = hashset_contains(set, hash_md5(payload));`,
		},
		{
			"a digest recorded in a report",
			`let row = {"path": p, "md5": hash_md5(payload)};`,
		},
		{
			"a digest printed",
			`putln("md5:", hash_md5(payload));`,
		},
		{
			// Whether this came from a manifest, from another tool, or from
			// the same run is not knowable here.
			"a digest compared with a value from somewhere else",
			`let ok = hash_md5(payload) == manifest["md5"];`,
		},
		{
			"a digest compared with another computed value",
			`let ok = hash_md5(payload) == expected_digest;`,
		},
		{
			"a strong hash against a written digest",
			`let ok = hash_sha256(payload) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";`,
		},
		{
			"an HMAC over SHA-256",
			`let mac = hmac(key, message, "sha256");`,
		},
		{
			"an HMAC whose algorithm is computed",
			`let mac = hmac(key, message, chosen);`,
		},
		{
			"a shadowed builtin",
			`let hash_md5 = fn(x) { return x; };
let ok = hash_md5(payload) == "5d41402abc4b2a76b9719d911017c592";`,
		},
		{
			// imphash is MD5 by the definition of the artifact, and nt_hash is
			// MD4. Reporting either would be reporting the format.
			"an import hash compared with a known value",
			`let ok, err = imphash(pe);`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if messages := weakCryptoMessages(t, tc.src); len(messages) != 0 {
				t.Fatalf("want silence, got %v", messages)
			}
		})
	}
}

func TestWeakCryptoCanBeTurnedOff(t *testing.T) {
	src := `let ok = hash_md5(payload) == "5d41402abc4b2a76b9719d911017c592";`

	config := DefaultLintConfig()
	config.WeakCrypto = LintSeverityOff

	snapshot := New().Analyze(src)
	for _, d := range Diagnostics(snapshot, config) {
		if strings.Contains(d.Message, "authenticity check") {
			t.Fatalf("rule is off but still reported: %s", d.Message)
		}
	}
}
