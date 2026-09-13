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
// A new evidence family belongs on this list. Leaving it off is not caught by
// anything -- that is the one soft edge of this policy, and the reason the list
// is a declaration in source rather than a pattern match on file names.
var EvidenceReadOnlyFiles = []string{
	// disk images, volumes and partition tables
	"builtin/disk_image_parsers.go",
	"builtin/filesystem_parsers.go",
	"builtin/table_parsers.go",
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
		File: "builtin/filesystem_parsers.go", Func: "ReadFile", Lines: 2,
		Why: "libxfat extracts only to a path, so an exFAT file's content round-trips " +
			"through os.CreateTemp and is removed in a defer. The volume is never written to.",
	},
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
}
