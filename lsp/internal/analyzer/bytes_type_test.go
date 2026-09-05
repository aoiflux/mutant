package analyzer

import (
	"strings"
	"testing"
)

// The reason the BYTES type exists, seen from the editor: a buffer handed to a
// builtin that will rune-decode it. str_reverse turns every byte that is not
// valid UTF-8 into U+FFFD and reports no error, so this diagnostic is the only
// thing standing between the program and a plausible wrong answer.
func TestBinaryIntoATextBuiltinIsDiagnosed(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a buffer read from disk",
			src:  "let data, err = fs_read_bytes(\"disk.img\");\nstr_upper(data);\n",
			want: "argument 1 to `str_upper` must be STRING, got BYTES",
		},
		{
			name: "a buffer that would be rune-reversed",
			src:  "let data, err = fs_read_bytes(\"disk.img\");\nstr_reverse(data);\n",
			want: "argument 1 to `str_reverse` must be STRING, got BYTES",
		},
		{
			name: "a decoded buffer",
			src:  "let raw, err = hex_decode_bytes(\"4d5a\");\nstr_substr(raw, 0, 2);\n",
			want: "argument 1 to `str_substr` must be STRING, got BYTES",
		},
		{
			name: "a span of a disk image",
			src:  "let sector, err = raw_read_at_bytes(h, 0, 512);\nregex_match(sector, \"MZ\");\n",
			want: "argument 1 to `regex_match` must be STRING, got BYTES",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := argTypeMessages(t, tc.src)
			for _, m := range msgs {
				if strings.HasPrefix(m, tc.want) {
					return
				}
			}
			t.Fatalf("expected a diagnostic starting %q, got %+v", tc.want, msgs)
		})
	}
}

// The message names the repair, because the conversion is deliberately explicit
// and so cannot be guessed from "must be STRING, got BYTES" alone.
func TestBinaryIntoTextNamesTheConversion(t *testing.T) {
	msgs := argTypeMessages(t, "let data, err = fs_read_bytes(\"disk.img\");\nstr_upper(data);\n")

	for _, m := range msgs {
		if strings.Contains(m, "got BYTES") {
			if !strings.Contains(m, `bytes_to_string(value, "utf8")`) {
				t.Errorf("the diagnostic does not name the conversion: %q", m)
			}
			return
		}
	}
	t.Fatalf("no BYTES diagnostic was produced: %+v", msgs)
}

// The other direction must stay quiet: the whole bytes_* family accepts either
// representation, so a buffer reaching one of them is correct code. A rule that
// fired here would be worse than no rule.
func TestBuffersIntoBinaryBuiltinsAreSilent(t *testing.T) {
	sources := []string{
		"let data, err = fs_read_bytes(\"disk.img\");\nlet n, e2 = bytes_len(data);\n",
		"let data, err = fs_read_bytes(\"disk.img\");\nlet head, e2 = bytes_slice(data, 0, 64);\n",
		"let data, err = fs_read_bytes(\"disk.img\");\nlet ok, e2 = fs_write(\"out.bin\", data);\n",
		"let data, err = fs_read_bytes(\"disk.img\");\nlet text, e2 = bytes_to_string(data, \"utf8\");\n",
		// The pre-BYTES spelling of all of the above still type-checks.
		"let data, err = fs_read(\"notes.txt\");\nlet n, e2 = bytes_len(data);\n",
	}

	for _, src := range sources {
		if msgs := argTypeMessages(t, src); len(msgs) != 0 {
			t.Errorf("%q produced %+v, want none", src, msgs)
		}
	}
}

// The lattice has to name the type for hover, inlay hints and completion detail
// to say anything useful about a buffer.
func TestBytesTypeIsInferredAndNamed(t *testing.T) {
	if got := (Type{Kind: TypeBytes}).String(); got != "bytes" {
		t.Errorf("Type.String() = %q, want %q", got, "bytes")
	}

	// Column 4 is `data`, the value half of the (value, err) pair.
	if got := typeAt(t, `let data, err = fs_read_bytes("disk.img");`, 0, 4); got != "bytes" {
		t.Errorf("fs_read_bytes bound `data` as %q, want %q", got, "bytes")
	}

	// Concatenation of two buffers is a buffer; a buffer and a string do not
	// add at all, and Any is the honest answer for an expression the VM refuses.
	if got := infixType("+", Type{Kind: TypeBytes}, Type{Kind: TypeBytes}); got.Kind != TypeBytes {
		t.Errorf("bytes + bytes inferred as %s, want bytes", got)
	}
	if got := infixType("+", Type{Kind: TypeBytes}, Type{Kind: TypeString}); got.Kind != TypeAny {
		t.Errorf("bytes + string inferred as %s, want any", got)
	}
}
