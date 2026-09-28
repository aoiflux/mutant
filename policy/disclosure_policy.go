package policy

// The third machine-checked policy in this package: the code that handles
// classified plaintext does not render it into text.
//
// A classified record's plaintext passes through a handful of files: the ones
// that open a segment, read a span, issue a grant, bundle a disclosure or
// verify one. In those files there are exactly two ways a byte of plaintext
// becomes part of a log line, a manifest, an error message or a report
// without anybody meaning it to:
//
//   - Inspect. On a buffer it renders the entire contents as hex -- it has to,
//     because it is the identity function for equality (see
//     object/bytesObj.go) -- so an Inspect call on the wrong value is a
//     complete disclosure in a string.
//   - A format string that is not a constant. fmt.Sprintf(plaintext) is a
//     disclosure by construction, and so is newError(anything assembled at
//     run time), and a reviewer reading a call cannot tell which it is
//     without tracing where the string came from.
//
// TestDisclosureCodeNeverRendersPlaintext makes both absent from these files a
// fact the build checks. It is the static half of the enforcement; the runtime
// half is object.Bytes.Classified, checked at every builtin that sends a value
// out of the process (builtin/classified.go). Neither is a taint analysis, and
// docs/DISCLOSURE_POLICY.md says so.

// DisclosureFiles are the files that handle classified plaintext or the key
// material that opens it.
//
// A new file in the record, grant or disclosure families belongs on this list.
// A file that names the key material -- the case key, the class-tag key, a
// grant or record-key operation, a passphrase request, the mark a read carries
// -- and is left off it fails TestEveryFileHoldingKeyMaterialIsGuarded. A file
// that handles plaintext without naming any of those is not caught, which is
// why the list is still a declaration in source.
var DisclosureFiles = []string{
	// the key schedule, the container and the grant
	"security/record_crypto.go",
	"security/record_file.go",
	"security/record_grant.go",
	// the case key, where its passphrase comes from, the case session that
	// holds it, and the classification scheme
	"builtin/case_key.go",
	"case_key_passphrase.go",
	"builtin/custody.go",
	"builtin/class.go",
	// the roles an examiner asserts and a recipient is named under
	"builtin/role.go",
	// sealing, opening, reading and searching records, and what a read is
	// marked with
	"builtin/record.go",
	"builtin/record_read.go",
	"builtin/record_search.go",
	"builtin/classified.go",
	// views and disclosures
	"builtin/view.go",
	"builtin/disclose.go",
	"builtin/disclose_history.go",
	"builtin/disclose_ledger.go",
	"builtin/disclose_reclassify.go",
	// the case in its ledger, which tags a read-back class under the case key,
	// and the custody of its exhibits
	"builtin/case_lifecycle.go",
	"builtin/case_chain.go",
	"builtin/case_evidence.go",
	// recipient roles, whose bundles name views under the case key, and the
	// versions of a record's redaction
	"builtin/recipient_role.go",
	"builtin/redaction_version.go",
	// the classes a script's ledger node holds, and the ledger read under a view
	"builtin/ledger_classify.go",
	"builtin/ledger_view.go",
	// the review of redactions made before the disclosure schema was guarded,
	// which every grant waits on
	"builtin/ledger_redaction_review.go",
	// the reviews of a case, its records and its redaction versions, and how
	// long the case is kept and what holds it
	"builtin/case_review.go",
	"builtin/case_retention.go",
}

// DisclosureFormatFuncs are the calls whose format argument must be a constant
// in DisclosureFiles, and which argument that is. `newError` is the builtin
// package's own Sprintf-shaped error constructor.
var DisclosureFormatFuncs = map[string]int{
	"fmt.Sprintf": 0,
	"fmt.Printf":  0,
	"fmt.Errorf":  0,
	"fmt.Fprintf": 1,
	"fmt.Appendf": 1,
	"newError":    0,
}
