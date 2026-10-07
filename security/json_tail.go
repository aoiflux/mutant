package security

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// RefuseTrailingContent reports whether anything but whitespace follows the
// document a decoder has just read.
//
// A file this build verifies holds one document. Of the eleven json.NewDecoder
// sites in this tree, seven decoded the first value and stopped without looking
// further, and four asked Decoder.More(); bytes past the first value were
// therefore never looked at, never hashed and never covered by the signature
// the verifier went on to report as holding. The file was reported verified,
// and a second document sitting behind the first was what the reader believed
// they had checked. Four of the seven read a sealed or signed document and are
// fixed through this function (M26-CUS-026), as are the three of the four that
// read one and asked More(), for the reason below. The remaining four are
// general-purpose parsers rather than verifiers: json_parse and ndjson_parse
// are M26-DAT-017's, and jwt_decode and reg_open claim no verification.
//
// `what` names the thing being read, in the lower case of a sentence's middle
// -- "the case manifest", "the grant file" -- because the message is built
// around it, and a message that says "the file" to an examiner holding six
// files is a message that has to be guessed at.
//
// Trailing whitespace is accepted, and that is not a nicety. A rewrite
// interrupted between the truncate and the write leaves a key file padded with
// newlines; refusing to open it would turn a survivable crash into a lost case
// key, which is a worse outcome than the one this function exists to prevent.
//
// Token() is the check, and decoder.More() is not enough. More() is what three
// of these parsers already used, and the standard library defines it as
//
//	c, err := dec.peek(); return err == nil && c != ']' && c != '}'
//
// so a document followed by a single '}' reports that there is nothing more to
// read -- and every byte after that '}' is then never examined at all. Under
// More() alone, `{"a":1}}` followed by anything whatsoever, a whole second JSON
// document included, is accepted in silence. That is not an academic gap for a
// document whose authentication is computed over a canonical form rebuilt from
// the decoded fields, which CaseKeyFile.CanonicalFile and GrantFile.canonical
// both are, field by length-prefixed field: nothing else in the program is
// looking at the file's own bytes either, so a byte More() skips is a byte no
// MAC, no signature and no digest in this package would ever see.
//
// Token() returns io.EOF only when the input is genuinely spent, and returns
// the offending token or a parse error for every other tail, which is why the
// offset below can be named.
//
// What Token() costs, stated because this package refuses elsewhere to let a
// parse allocate on an unauthenticated file's say-so: for a tail that opens
// with a delimiter it returns that delimiter and reads no further, but for a
// tail that is a bare scalar it decodes the scalar before handing it back, so a
// document followed by a 500 MB string literal is decoded and then refused.
// That is bounded here and not left to chance: every caller already holds the
// whole buffer in memory -- os.ReadFile for the manifest, the audit log and the
// key file, a size-checked read for the disclosure manifest and the grant file,
// a length-prefixed span for the record header and footer -- so the worst case
// is a second copy of bytes that are already resident, not an allocation a file
// dictated.
//
// InputOffset is read before Token() and not after, because Token() skips the
// whitespace in front of whatever it finds. It is also why nothing here calls
// More(): Go 1.26 carries two implementations of encoding/json, and in the
// jsonv2 one InputOffset reports the start of the next token rather than the
// end of the last one once More() has been called (v2_stream.go). Nothing in
// this tree sets that experiment, but an offset that moves under a build tag is
// an offset that would be reported wrongly the day somebody flips it.
func RefuseTrailingContent(decoder *json.Decoder, what string) error {
	end := decoder.InputOffset()
	token, err := decoder.Token()
	// errors.Is rather than ==, because the only thing this branch must never
	// do is miss a genuine end of input: a wrapped io.EOF read as a tail would
	// refuse every well-formed file there is.
	if errors.Is(err, io.EOF) {
		return nil
	}
	var found string
	switch {
	case err != nil:
		// A stray '}' or ']' lands here rather than above: Token() will not
		// return a closing delimiter that opens nothing, so the tail is
		// reported as the parse error it is.
		found = err.Error()
	default:
		if delim, ok := token.(json.Delim); ok {
			found = fmt.Sprintf("another document, opening with %q", string(delim))
		} else {
			found = fmt.Sprintf("another value, %v", token)
		}
	}
	return fmt.Errorf("%s ends at byte %d and something follows it: %s. A file this build verifies "+
		"holds one document, and anything after it is content that nothing checked", what, end, found)
}
