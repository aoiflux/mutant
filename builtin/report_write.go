package builtin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mutant/object"
)

// --- writing a report out ---
//
// Everything in report.go is a value: a report is built, rendered, and handed
// back as a string. This is where one leaves the process, and two things change
// when it does.
//
// The first is that the document acquires a digest. A report is written to be
// given to somebody -- opposing counsel, a client, the next examiner -- and the
// only useful thing to say about a file that has left your hands is what it
// hashed to when it left them. So `report_write` returns one, and the case
// manifest records it.
//
// The second is F-1's rule: a claim is only worth the check behind it. The
// digest here is taken by reading the file back off the disk, not by hashing the
// buffer that was meant to become it, and it is then checked against that
// buffer. A short write, a full disk, a filter driver that rewrote the bytes on
// the way past -- each of those produces a file whose digest is not the one the
// program would have reported, and each of them is now a refusal instead.

// reportExtensionFormats maps a path's extension to the rendering it asks for.
// An examiner naming a file report.html has already said what they want; making
// them say it twice is how `{"format": "csv"}` ends up on a file called .html.
var reportExtensionFormats = map[string]string{
	".html":     "html",
	".htm":      "html",
	".md":       "markdown",
	".markdown": "markdown",
	".csv":      "csv",
}

// reportWriteOptions is `report_render`'s option set plus the one thing writing
// adds: an explicit format, for a path whose extension says nothing.
var reportWriteOptions = append([]string{"format"}, reportRenderOptions...)

// ReportWrite renders a report and writes it: report_write(report, path, opts?).
func ReportWrite(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	reportHash, errObj := requireHashArg("report_write", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg("report_write", args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("report_write: the path must not be empty"))
	}
	opts, errObj := formatOptionsArg("report_write", args, 3, reportWriteOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	format, errObj := reportWriteFormat(path, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// Rendered before anything is created, so a document with a block nothing
	// renders leaves no half-written file behind for someone to find later and
	// take for a report.
	text, errObj := renderReport("report_write", reportHash, format, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	written, errObj := writeArtifact("report_write", path, []byte(text))
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The case, if one is open, records that this report exists and what it
	// hashed to. That is the whole of the link between an investigation and the
	// documents it produced: the manifest can be checked, and it names a digest
	// the report either still has or does not.
	custodyRecordArtifact("report_write",
		fmt.Sprintf("wrote %s as %s (%d bytes, sha256 %s)", path, format, written.bytes, written.digest),
		map[string]any{
			"path":   path,
			"format": format,
			"bytes":  written.bytes,
			"sha256": written.digest,
		})

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":   stringObj(path),
		"bytes":  intObj(written.bytes),
		"format": stringObj(format),
		"sha256": stringObj(written.digest),
	}), nil)
}

// reportWriteFormat decides what to render, from the option if it is there and
// from the extension otherwise.
func reportWriteFormat(path string, opts *formatOptions) (string, *object.Error) {
	format, errObj := opts.str("format", "")
	if errObj != nil {
		return "", errObj
	}
	if strings.TrimSpace(format) != "" {
		return format, nil
	}

	if named, ok := reportExtensionFormats[strings.ToLower(filepath.Ext(path))]; ok {
		return named, nil
	}

	extensions := make([]string, 0, len(reportExtensionFormats))
	for extension := range reportExtensionFormats {
		extensions = append(extensions, extension)
	}
	sort.Strings(extensions)
	return "", newError("%s: nothing in %q says which format to write; give the path one of %s, or pass {%q: %q}",
		opts.op, filepath.Base(path), strings.Join(extensions, ", "), "format", reportFormats[0])
}

// writtenArtifact is what a file turned out to be once it was on disk.
type writtenArtifact struct {
	bytes  int64
	digest string
}

// writeArtifact writes a document and reports what the file it produced hashes
// to -- measured from the file, then checked against the bytes that were meant
// to be in it.
//
// Hashing the buffer instead would be faster and would be a claim about an
// intention. The digest of a document handed to someone else has to be a claim
// about the document, which means reading back what the filesystem actually
// kept. The mode is 0600 for the same reason `case_write` uses it: a report
// names evidence, and the default umask is not a decision anybody made.
func writeArtifact(op, path string, data []byte) (writtenArtifact, *object.Error) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}

	// Streamed rather than read into memory: the same file that holds a
	// paragraph today holds a table of every record in an $MFT tomorrow.
	digest, err := custodyHashFile(path, "sha256")
	if err != nil {
		return writtenArtifact{}, newError("%s: %s was written but cannot be read back to hash it: %s", op, path, err.Error())
	}

	expected := sha256.Sum256(data)
	if digest != hex.EncodeToString(expected[:]) {
		return writtenArtifact{}, newError(
			"%s: %s is not what was written; it hashes to %s and the document hashes to %s. "+
				"Something changed the file between the write and the read, and the digest of a document nobody can reproduce is worth nothing",
			op, path, digest, hex.EncodeToString(expected[:]))
	}

	info, err := os.Stat(path)
	if err != nil {
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}
	return writtenArtifact{bytes: info.Size(), digest: digest}, nil
}
