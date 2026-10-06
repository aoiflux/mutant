package policy

// The second machine-checked policy in this package (F-1): Mutant does not
// modify evidence.
//
// The invariant already held when it was written down. Every image, volume,
// hive and archive backend opens its source with os.Open, and nothing in the
// evidence-reading code asks the operating system to create, truncate, rename,
// delete or chmod anything -- with the two reviewed exceptions below, neither of
// which touches the source. But an invariant that holds by accident is not a
// guarantee an examiner can testify to, and the next patch could quietly end it.
// TestEvidenceCodeNeverWrites makes it a fact.
//
// The prose version, with the reasoning, is in docs/EVIDENCE_HANDLING_POLICY.md.
//
// **Why the guard does not look for `Write`.** A write to a file needs a handle
// opened for writing, and the only three ways to get one -- os.Create,
// os.CreateTemp, and os.OpenFile with anything but O_RDONLY -- are all on the
// list below. So catching the *opening* catches the writing, and the guard does
// not have to decide whether a bare `.Write(...)` is going to a file, a hash or
// a string builder. A rule that cannot produce a false positive is a rule nobody
// switches off.

// EvidenceReadOnlyFiles are the files that read evidence: disk images, volumes,
// partition tables, registry hives, archives, and the Windows, Unix and browser
// artifact parsers.
//
// A new evidence family belongs on this list. For the image and filesystem
// family, leaving it off is now caught: TestEveryImageReaderIsUnderTheGuard
// derives the set from three structural facts -- an import of an aoiflux lib*
// or partition package, a use of the fsRegion type that every *_open goes
// through, and a use of the fsFileReader type the streaming reads go through --
// and fails when a file with one of them is absent from this list. That rule
// found twelve omissions when it was written, among them
// builtin/filesystem_region.go, which holds the os.Open behind every *_open
// family, and builtin/filesystem_recover.go, the only code in the evidence path
// that creates and removes files (M26-TEST-009).
//
// The soft edge that remains is narrower and worth stating exactly. A parser of
// a captured artifact -- an EVTX log, a LNK, a plist -- has no structural marker
// in common with the others: it opens a path and reads bytes, like most of the
// standard library does. Those entries are still a judgement, and leaving one
// off is still caught by nothing. What changed is that the judgement is no
// longer load-bearing for the family the policy was written for.
var EvidenceReadOnlyFiles = []string{
	// disk images, volumes and partition tables
	"builtin/disk_image_parsers.go",
	"builtin/disk_image_extents.go",
	"builtin/filesystem_parsers.go",
	"builtin/table_parsers.go",
	// the seams every filesystem open and every streaming read goes through:
	// fsRegion bounds the part of an image a filesystem occupies, and
	// fsFileReader is how a file inside one is read out
	"builtin/filesystem_region.go",
	"builtin/filesystem_stream.go",
	// what a mounted filesystem is asked for, family by family
	"builtin/filesystem_capabilities.go",
	"builtin/filesystem_deleted.go",
	"builtin/filesystem_journal.go",
	"builtin/filesystem_recover.go",
	"builtin/filesystem_report.go",
	"builtin/filesystem_slack.go",
	"builtin/filesystem_verify.go",
	"builtin/filesystem_xattr.go",
	// type identification on a path the examiner named
	"builtin/fs_forensics.go",
	// registry
	"builtin/registry_forensics.go",
	"builtin/hive_builtins.go",
	"builtin/amcache_builtins.go",
	"builtin/shimcache_builtins.go",
	// archives
	"builtin/archive.go",
	// Windows execution and filesystem artifacts
	"builtin/mft_builtins.go",
	"builtin/evtx_builtins.go",
	"builtin/prefetch_builtins.go",
	"builtin/lnk_builtins.go",
	"builtin/jumplist_builtins.go",
	// databases and browser artifacts
	"builtin/sqlite_builtins.go",
	"builtin/browser_builtins.go",
	// other captured artifacts
	"builtin/bodyfile_builtins.go",
	"builtin/plist_builtins.go",
	"builtin/syslog_builtins.go",
	"builtin/email_forensics.go",
	"builtin/fs_deleted_builtins.go",
	// live subjects
	"builtin/memory_forensics.go",
	// custody of exhibits: a file taken in or accepted is hashed, and a
	// disposal is a statement that deletes nothing
	"builtin/case_evidence.go",
	// where an open is recorded against the exhibit it was made on
	"builtin/custody.go",
}

// EvidenceWriteException records a place in that code where a filesystem
// mutation is legitimate, and why.
//
// The bar is that the write must not touch the evidence. Both current entries
// meet it by writing somewhere else entirely -- a temp file the library demands,
// and a temp copy taken so the original is never opened by something that would
// want to write to it.
type EvidenceWriteException struct {
	// File is the repository-relative path, with forward slashes.
	File string
	// Func is the enclosing top-level function or method.
	Func string
	// Lines is the exact number of source lines in Func that may mutate the
	// filesystem. Pinning the count means a new write added inside an
	// already-allowlisted function still fails the guard.
	Lines int
	// Why explains what makes this write something other than evidence
	// modification.
	Why string
}

// EvidenceWriteAllowlist is the complete set of permitted mutations in the files
// above.
//
// Adding an entry is a policy decision. The question to answer in the commit is
// not "is this write safe?" but "which bytes does it touch, and are they the
// examiner's or the evidence's?"
var EvidenceWriteAllowlist = []EvidenceWriteException{
	{
		File: "builtin/sqlite_builtins.go", Func: "withSQLiteCopy", Lines: 2,
		Why: "This is the policy in action rather than an exception to it: SQLite wants to " +
			"write a journal beside any database it opens, so the evidence database is " +
			"copied into os.MkdirTemp and queried there. The copy is removed in a defer.",
	},
	{
		File: "builtin/sqlite_builtins.go", Func: "copyFileContents", Lines: 1,
		Why: "The os.Create that makes the temp copy withSQLiteCopy queries. The destination " +
			"is the temp path; the source is opened read-only.",
	},
	{
		File: "builtin/filesystem_recover.go", Func: "fsWriteEvidenceFile", Lines: 2,
		Why: "Recovery writes the file it recovered, which is the point of recovering it. The " +
			"destination is a path the examiner named for output and never the image: the open " +
			"is O_WRONLY|O_CREATE|O_EXCL, so it refuses to write over anything that is already " +
			"there, and the os.Remove on the second line only undoes a destination this " +
			"function created moments earlier and then failed to fill. Neither line can reach " +
			"the evidence, because the image is open read-only in another handle entirely.",
	},
}
