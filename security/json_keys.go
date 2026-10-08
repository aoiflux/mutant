package security

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RefuseRepeatedKeys reports whether any object in a document names the same
// field twice.
//
// A file this build verifies holds each name once. encoding/json keeps the
// LAST of two identically-named fields and drops the first without a word, and
// it does so decoding into a map and decoding into a struct alike --
// DisallowUnknownFields does not catch it, because the name is known, it is
// simply there twice. Four readers in this build then authenticate a document
// over a form they REBUILD from what the decoder kept: custodyCanonical
// re-marshals the manifest map, and CaseKeyFile.CanonicalFile and
// GrantFile.canonical rebuild field by length-prefixed field. So the first copy
// of a repeated name is a byte no digest, no MAC and no signature in this
// package ever sees, and the document goes on verifying.
//
// Measured before this function existed: an honest sealed manifest of 98 bytes
// and a forged one of 119, differing only by `"examiner":"Mallory",` inserted in
// front of the real examiner, produced byte-identical canonical forms, the
// identical SHA-256, and one Ed25519 signature that verified against both
// (M26-CUS-032). case_manifest_verify reported hash_matches, signed and
// signature_valid on the forged file and read back the honest examiner, while
// the bytes an examiner opens in a text editor said Mallory. No key is needed
// for that edit; a text editor is the whole tool chain.
//
// It refuses rather than choosing the first copy. Picking a copy would be a
// silent reinterpretation of a document somebody signed, and this build's rule
// is that a refusal is fine where a silent drop is not. Refusing costs nothing
// that is in use: json.Marshal cannot emit a repeated name, so no document
// Mutant has ever written is refused by this check.
//
// `what` names the thing being read, in the lower case of a sentence's middle,
// for the reason RefuseTrailingContent gives: a message that says "the file" to
// an examiner holding six files is a message that has to be guessed at.
//
// Every depth is checked, not just the top level. A second manifest_hash inside
// the `seal` block is the same defect as a second examiner beside it, and the
// one that is harder to see.
//
// What it does NOT report, stated because it is load-bearing: a malformed
// document, and anything following the document. Token() failing for any reason
// -- a bad escape, a truncated object, or a genuine end of input -- returns nil
// from here and leaves the message to the caller's own Decode, which already
// has one and words it for the file it is reading. RefuseTrailingContent
// answers the tail. This function answers one question, so that adding it
// changes no message a user sees today except on a document that repeats a
// name.
//
// Cost, stated because this package refuses elsewhere to let a parse allocate
// on an unauthenticated file's say-so: one more pass over bytes the caller
// already holds in memory and has already bounded -- os.ReadFile for the
// manifest and the key file, a size-checked read for the disclosure manifest
// and the grant file -- plus one set of names per object open at the moment,
// which no document can make larger than the document itself. Nothing here is
// sized from a number the file states.
func RefuseRepeatedKeys(data []byte, what string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	// One frame per container currently open, innermost last. A nil frame is an
	// array: it has no names of its own, but a value inside it can be an object
	// that has.
	var open []*objectFrame

	for {
		token, err := decoder.Token()
		if err != nil {
			return nil // including io.EOF; see the comment above
		}

		if frame := innermostObject(open); frame != nil && frame.expectName {
			if name, ok := token.(string); ok {
				if _, repeated := frame.names[name]; repeated {
					return fmt.Errorf("%s names %q twice in one object, and the second spelling ends at "+
						"byte %d. A file this build verifies holds each name once: this reader keeps the "+
						"last copy, so the first is a value somebody can read and nothing checked",
						what, name, decoder.InputOffset())
				}
				frame.names[name] = struct{}{}
				frame.expectName = false
				continue
			}
			// The only other token an object can produce where a name is due is
			// its own closing '}', which the delimiters below pop.
		}

		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				open = append(open, &objectFrame{names: map[string]struct{}{}, expectName: true})
				continue
			case '[':
				open = append(open, nil)
				continue
			default: // '}' or ']', closing the innermost container
				open = open[:len(open)-1]
			}
		}

		// A value is complete -- a scalar, or the container just popped -- so an
		// enclosing object is owed a name next.
		if frame := innermostObject(open); frame != nil {
			frame.expectName = true
		}
		if len(open) == 0 {
			return nil // the document's one top-level value is complete
		}
	}
}

// objectFrame is one JSON object that is open: the names seen in it so far, and
// whether the next token is a name rather than a value. Tracking that is what
// keeps a string VALUE of "examiner" from being counted as a second field named
// examiner.
type objectFrame struct {
	names      map[string]struct{}
	expectName bool
}

// innermostObject is the open container if it is an object, and nil if it is an
// array or if nothing is open.
func innermostObject(open []*objectFrame) *objectFrame {
	if len(open) == 0 {
		return nil
	}
	return open[len(open)-1]
}
