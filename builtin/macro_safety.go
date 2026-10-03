package builtin

import (
	"slices"
	"strings"
)

// This file is the macro-expansion trust boundary: the list of builtins a macro
// body may call while the compiler is running, and the reason every other one is
// refused.
//
// Why the boundary exists. A macro body is evaluated during compilation --
// during `mutant gen`, `mutant test`, a debug session's launch, and the compile
// of every module in the linked graph, so a macro in an imported library runs at
// the importer's compile. None of the run time's controls exist yet at that
// point: no password has been asked for, no posture has been chosen, and the
// program has not been started. "Compile this" is not "run this", and the
// difference has to be enforced somewhere.
//
// The membership test, applied by hand and name by name. A builtin is macro-safe
// only when all six hold:
//
//  1. Deterministic. The same arguments give the same result on every compile.
//     Expansion writes source into the artifact, so a non-deterministic builtin
//     makes the build unreproducible as well as unsafe.
//  2. No ambient read: no filesystem, network, process, registry, clock, entropy
//     or standard input.
//  3. No ambient write: no file, no socket, no standard output, and no
//     process-global store. This clause, rather than I/O, is what refuses
//     policy_load and the cache family: they write state the compiled program
//     would then read back, in the same process for both REPLs.
//  4. No handle in and no handle out. A value is a handle when it names an entry
//     in a process-global table -- not merely when it is opaque. This is a
//     separate clause because handles here are spelled as plain INTEGER and
//     STRING, which are two of the five shapes unquote can bake into the program
//     the compiler then emits. A bytes cursor is not a handle by this test: it is
//     a HASH the program itself carries, which is also why it can never survive
//     into the emitted source.
//  5. Executor-native only when its sole effect is calling a user function that
//     this engine then evaluates, so the callback is gated by the same rule.
//  6. Bounded, or known not to be. See the note on str_repeat below -- this is
//     the one clause the current list does not fully satisfy, and it is recorded
//     rather than papered over.
//
// The shape: allow is enumerated BY NAME, refuse may be expressed BY FAMILY.
// Allow must never be a prefix, because a prefix allow would admit a future
// str_read_file on sight. Refuse may be a prefix, because auto-refusing a future
// fs_* is the safe direction. MacroSafe answers false for everything it was not
// told about -- a refused builtin, one nobody has classified, a name that is not
// a builtin at all, the empty string -- so there is no path through it that
// resolves to "allow".
//
// Deliberately NOT derived from CapabilityCategory. That function's own comment
// calls it a decorative label for editor hover, and it has no unknown state: an
// unmatched name comes back as "standard library", the same label as len, and
// that bucket holds with_resource and gets. Six of its categories mix pure
// builtins with ones that read a path or draw entropy. The categories were used
// to group the decisions below for review, and for nothing else.
//
// Deliberately NOT derived from webrepl.BrowserSafe either. That predicate ends
// in `return !needsHost`, so it admits anything it does not recognise -- which is
// how it admits lua_run_string, whose Lua sandbox registers a host file read.
//
// Where the line falls on parsers, which is the least obvious part of the list.
// Eleven builtins that parse attacker-controlled structure are allowed --
// json_parse, ndjson_parse, yaml_parse, yaml_parse_all, xml_parse, csv_parse,
// cbor_parse, msgpack_parse, toml_parse, protobuf_parse and time_parse -- because
// a macro that writes code from a table it carries is the main reason to have
// macros at all, and that table has to be spelled somewhere. The cryptographic
// decoders are refused instead: aes_*, x509_parse, jwt_decode, pem_decode and
// der_parse. der_parse is listed by name rather than caught by a family because
// it decodes the same wire format x509_parse does, and allowing one while
// refusing the other would have been a distinction with nothing behind it.
//
// That split is about what an attacker gains, not about parser quality: the
// allowed eleven are no better bounded than the refused five. toml_parse and
// msgpack_parse have no nesting limit, so a deep literal in a macro body crashes
// the compiler -- which is M26-DAT-004, an open finding against those parsers,
// and the place it has to be fixed. Narrowing this list instead would leave the
// same crash reachable from every other caller and call it closed.
//
// One implementation note that has bitten this package before: `help` is
// appended to Builtins inside init(), which runs after every package-level var
// initializer. So the two tables here are plain literals, and any map derived
// from Builtins is built inside the function that needs it, never as a package
// var. builtin/error_builtin.go's errorValuedBuiltins is the shape NOT to copy.
//
// Known and not closed: an allowlisted builtin can still exhaust the compiler.
// str_repeat hands its count straight to strings.Repeat with no cap, where range
// caps itself at ten million, so `str_repeat("x", 1<<40)` panics or allocates
// until the process dies -- with a Go stack trace, which is the failure class
// macro expansion's own comment says was fixed. That is a pre-existing bug in
// the builtin rather than one this boundary introduces (it does the same at run
// time), and it is filed separately, together with the fact that a macro body
// containing `while (true) {}` hangs the compiler regardless of which builtins
// it may call. Clause 6 is written above so the next author does not have to
// rediscover the gap.

const (
	reasonPureComputation     = "only pure computation is available while a macro is being expanded"
	reasonNotDeterministic    = "it is not deterministic, and expansion has to produce the same source on every compile"
	reasonProcessGlobal       = "it writes process-global state the compiled program would then read"
	reasonOpensAPath          = "it opens the file it is given the path of"
	reasonOpensAStore         = "it opens and writes a store on disk"
	reasonOpensAnImage        = "it opens a disk image"
	reasonStandardStreams     = "it reads or writes the standard streams"
	reasonInspectsTheSystem   = "it inspects the running system"
	reasonProcessGlobalHandle = "it registers a handle in a process-global table"
	reasonNoTestRun           = "there is no test run at compile time"
	reasonCryptoMaterial      = "it decodes untrusted cryptographic material"
	reasonTwoEngines          = "it is sequential in this engine and concurrent in the VM, so a macro would mean two different things"
)

// macroSafeBuiltins is every builtin a macro body may call. Grouped by family,
// with the reason each family qualifies; see the membership test above.
var macroSafeBuiltins = []string{
	// The core primitives: shapes, arithmetic, and the collection operations.
	// Every one of them works on a value the program is already holding.
	BuiltinNameLen, BuiltinNameFirst, BuiltinNameLast, BuiltinNameRest, BuiltinNamePush, BuiltinNamePop,
	BuiltinNameStringToBytes, BuiltinNameAbs, BuiltinNameMin, BuiltinNameMax, BuiltinNameClamp,
	BuiltinNamePow, BuiltinNameSqrt, BuiltinNameMod, BuiltinNameFloor, BuiltinNameCeil, BuiltinNameRound,
	BuiltinNameSum, BuiltinNameAvg, BuiltinNameTypeOf, BuiltinNameIsNull, BuiltinNameError, BuiltinNameSort,
	BuiltinNameReverseArray, BuiltinNameContains, BuiltinNameIndexOf, BuiltinNameSlice, BuiltinNameConcat,
	BuiltinNameFlatten, BuiltinNameUnique, BuiltinNameRange, BuiltinNameZip, BuiltinNameKeys,
	BuiltinNameValues, BuiltinNameEntries, BuiltinNameHasKey, BuiltinNameGet, BuiltinNameSet,
	BuiltinNameMerge, BuiltinNameDelete, BuiltinNameIntToIP,

	// Strings.
	BuiltinNameStrUpper, BuiltinNameStrLower, BuiltinNameStrTrim, BuiltinNameStrTrimLeft,
	BuiltinNameStrTrimRight, BuiltinNameStrTrimPrefix, BuiltinNameStrTrimSuffix, BuiltinNameStrStartsWith,
	BuiltinNameStrEndsWith, BuiltinNameStrJoin, BuiltinNameStrRepeat, BuiltinNameStrPadLeft,
	BuiltinNameStrPadRight, BuiltinNameStrReverse, BuiltinNameStrSubstr, BuiltinNameStrCharAt,
	BuiltinNameStrFormat, BuiltinNameStrTitle,

	// Bytes, and the cursor over them. A cursor is a HASH carrying `data` and
	// `offset` that the program itself holds -- not a handle -- so it neither
	// names a process-global entry nor survives into the emitted program.
	BuiltinNameBytesLen, BuiltinNameBytesGet, BuiltinNameBytesSlice, BuiltinNameBytesReadU16Le,
	BuiltinNameBytesReadU16Be, BuiltinNameBytesReadU32Le, BuiltinNameBytesReadU32Be,
	BuiltinNameBytesReadU64Le, BuiltinNameBytesReadU64Be, BuiltinNameBytesWriteU16Le,
	BuiltinNameBytesWriteU16Be, BuiltinNameBytesWriteU32Le, BuiltinNameBytesWriteU32Be,
	BuiltinNameBytesWriteU64Le, BuiltinNameBytesWriteU64Be, BuiltinNameBytesCstrAt, BuiltinNameBytesHex,
	BuiltinNameBytesCharFromInt, BuiltinNameBytesIntFromChar, BuiltinNameBytesCursorNew,
	BuiltinNameBytesCursorTell, BuiltinNameBytesCursorSeek, BuiltinNameBytesCursorEof,
	BuiltinNameBytesCursorReadU8, BuiltinNameBytesCursorReadU16Le, BuiltinNameBytesCursorReadU16Be,
	BuiltinNameBytesCursorReadU32Le, BuiltinNameBytesCursorReadU32Be, BuiltinNameBytesCursorReadU64Le,
	BuiltinNameBytesCursorReadU64Be, BuiltinNameBytesToString,

	// Text and regular expressions.
	BuiltinNameTextContains, BuiltinNameTextIndex, BuiltinNameTextCount, BuiltinNameTextSplit,
	BuiltinNameTextReplace, BuiltinNameTextLevenshtein, BuiltinNameTextSimilarity, BuiltinNameTextFuzzyFind,
	BuiltinNameTextJaroWinkler, BuiltinNameRegexMatch, BuiltinNameRegexFind, BuiltinNameRegexFindAll,
	BuiltinNameRegexReplace, BuiltinNameRegexCaptureGroups,

	// Encodings and structured formats. Every one of them converts a value the
	// program passed in; plist_parse is the one in this family that takes a path,
	// and it is refused.
	BuiltinNameJsonStringify, BuiltinNameJsonParse, BuiltinNameBase64Encode, BuiltinNameBase64Decode,
	BuiltinNameBase64DecodeBytes, BuiltinNameBase64URLEncode, BuiltinNameBase64URLDecode,
	BuiltinNameBase32Encode, BuiltinNameBase32Decode, BuiltinNameHexEncode, BuiltinNameHexDecode,
	BuiltinNameHexDecodeBytes, BuiltinNameURLEncode, BuiltinNameURLDecode, BuiltinNameGzip, BuiltinNameGunzip,
	BuiltinNameGunzipBytes, BuiltinNameZlibCompress, BuiltinNameZlibDecompress,
	BuiltinNameZlibDecompressBytes, BuiltinNameCsvParse, BuiltinNameCsvStringify, BuiltinNameXmlParse,
	BuiltinNameXmlFind, BuiltinNameNdjsonParse, BuiltinNameNdjsonStringify, BuiltinNameYamlParse,
	BuiltinNameYamlParseAll, BuiltinNameYamlStringify, BuiltinNameTomlParse, BuiltinNameTomlStringify,
	BuiltinNameCborParse, BuiltinNameCborEncode, BuiltinNameMsgpackParse, BuiltinNameMsgpackEncode,
	BuiltinNameProtobufParse, BuiltinNameToBase, BuiltinNameFromBase, BuiltinNameToInt, BuiltinNameToFloat,
	BuiltinNameToString, BuiltinNameToBool, BuiltinNameParseInt, BuiltinNameParseFloat,

	// Digests and HMAC. Deriving a constant at expansion time is a real use, and
	// a digest grants nothing. The entropy-drawing members of this family --
	// uuid_v4, uuid_v7, random_hex, nanoid -- are refused, as is the aes/x509/jwt/pem
	// group, which decodes material the compiler was handed.
	BuiltinNameHashMD5, BuiltinNameHashSHA1, BuiltinNameHashSHA256, BuiltinNameHashSHA512,
	BuiltinNameHashCRC32, BuiltinNameHashBlake2, BuiltinNameHMAC,

	// Numbers. rand, rand_int and rand_bytes are refused; a constant is not a draw.
	BuiltinNameMathPi, BuiltinNameMathE,

	// Time arithmetic over a value the program supplied. time_format is UTC, so it
	// is machine-independent. Reading the clock -- time_now, time_unix, time_ms --
	// is refused.
	BuiltinNameTimeFormat, BuiltinNameTimeParse, BuiltinNameTimeDiff, BuiltinNameTimeAdd,

	// Indicators, addresses and names. All of them parse; none resolves anything.
	BuiltinNameDefang, BuiltinNameRefang, BuiltinNameIPIsPrivate, BuiltinNameIPInCIDR, BuiltinNameCIDRHosts,
	BuiltinNameIPVersion, BuiltinNameIPToInt, BuiltinNameDomainExtract, BuiltinNameTLDExtract,
	BuiltinNameIsValidDomain, BuiltinNameExtractIOCs,

	// Timelines assembled from rows the program already holds. bodyfile_parse,
	// which takes a path, is refused; mactime takes its rows.
	BuiltinNameTimestampNormalize, BuiltinNameTimelineSort, BuiltinNameTimelineMerge, BuiltinNameMactime,

	// Fingerprints computed from bytes or a string the program supplied. imphash,
	// which takes a path to a PE, is refused.
	BuiltinNameNTHash, BuiltinNameLMHash, BuiltinNameJA3,

	// Events rendered from values the program already holds. stix_bundle is refused:
	// its `created` field defaults to now, so two compiles of one source would not
	// produce the same bundle.
	BuiltinNameEventsFrom, BuiltinNameEventKinds, BuiltinNameEcsEvent, BuiltinNameOcsfEvent,
	BuiltinNameTimesketchEvent, BuiltinNameStixPattern,

	// The five higher-order builtins whose only effect is calling a function this
	// engine then evaluates -- so the callback, and everything the callback names,
	// is gated by the same rule. pmap and peach are refused for a different reason:
	// they are sequential here and concurrent in the VM, so allowing them would let
	// one macro mean two things.
	BuiltinNameMap, BuiltinNameFilter, BuiltinNameReduce, BuiltinNameEach, BuiltinNameSortBy,

	// serve_conn and serve_arg already answer an empty pair during expansion, and
	// the evaluator says so in as many words -- it is the same answer a program gets
	// when it runs outside a handler. Refusing them would retire a deliberate answer
	// and buy nothing: they take no arguments and reach nothing.
	BuiltinNameServeConn, BuiltinNameServeArg,
}

// macroRefusal is one rule about names that are not macro-safe. Either an exact
// name or a family prefix, and always a reason -- the clause the expander prints
// after "is not available at macro expansion time, because".
type macroRefusal struct {
	name   string
	prefix string
	why    string
}

// macroRefusals is read first match wins, so the exact names come before the
// families they sit inside. Its job is not to decide anything -- MacroSafe
// already did -- but to say WHY, and to make the drift guard able to tell a
// builtin somebody classified from one nobody has looked at.
var macroRefusals = []macroRefusal{
	{name: BuiltinNameWithResource, why: "it resolves a builtin by name from a string, so no rule that reads names can see what it would call"},
	{name: BuiltinNameSpawn, why: reasonProcessGlobalHandle},
	{name: BuiltinNameGets, why: reasonStandardStreams},
	{name: BuiltinNamePutln, why: reasonStandardStreams},
	{name: BuiltinNamePutf, why: reasonStandardStreams},
	{name: BuiltinNameHelp, why: reasonStandardStreams},
	{name: BuiltinNameSleepMs, why: "it stalls the compiler"},
	{name: BuiltinNameDebugStatus, why: "it reports on the running process"},
	{name: BuiltinNameSandboxStatus, why: "it reports on the running process"},
	{name: BuiltinNameSecurityDiagnostics, why: "it reports on the running process"},
	{name: BuiltinNamePMap, why: reasonTwoEngines},
	{name: BuiltinNamePEach, why: reasonTwoEngines},
	{name: BuiltinNameRand, why: reasonNotDeterministic},
	{name: BuiltinNameRandInt, why: reasonNotDeterministic},
	{name: BuiltinNameRandBytes, why: reasonNotDeterministic},
	{name: BuiltinNameRandomHex, why: reasonNotDeterministic},
	{name: BuiltinNameUUIDv4, why: reasonNotDeterministic},
	{name: BuiltinNameUUIDv7, why: reasonNotDeterministic},
	{name: BuiltinNameNanoID, why: reasonNotDeterministic},
	{name: BuiltinNameTimeNow, why: reasonNotDeterministic},
	{name: BuiltinNameTimeUnix, why: reasonNotDeterministic},
	{name: BuiltinNameTimeMs, why: reasonNotDeterministic},
	{name: BuiltinNameStixBundle, why: reasonNotDeterministic},
	{name: BuiltinNameImphash, why: reasonOpensAPath},
	{name: BuiltinNamePlistParse, why: reasonOpensAPath},
	{name: BuiltinNameBodyfileParse, why: reasonOpensAPath},
	{prefix: "fs_", why: "it reads and writes the filesystem"},
	{prefix: "exec_", why: "it runs a program"},
	{prefix: "cmd_", why: "it runs a program"},
	{prefix: "net_", why: "it reaches the network"},
	{prefix: "http_", why: "it reaches the network"},
	{prefix: "ws_", why: "it reaches the network"},
	{prefix: "tls_", why: "it reaches the network"},
	{prefix: "lua_", why: "it runs a Lua script, and that sandbox can still read files"},
	{prefix: "process_", why: reasonInspectsTheSystem},
	{prefix: "mem_", why: reasonInspectsTheSystem},
	{prefix: "policy_", why: reasonProcessGlobal},
	{prefix: "cache_", why: reasonProcessGlobal},
	{prefix: "chan_", why: reasonProcessGlobalHandle},
	{prefix: "task_", why: reasonProcessGlobalHandle},
	{name: BuiltinNameDerParse, why: reasonCryptoMaterial},
	{prefix: "aes_", why: reasonCryptoMaterial},
	{prefix: "x509_", why: reasonCryptoMaterial},
	{prefix: "jwt_", why: reasonCryptoMaterial},
	{prefix: "pem_", why: reasonCryptoMaterial},
	{prefix: "ledger_", why: reasonOpensAStore},
	{prefix: "record_", why: reasonOpensAStore},
	{prefix: "db_", why: reasonOpensAStore},
	{prefix: "case_", why: reasonOpensAStore},
	{prefix: "class_", why: reasonOpensAStore},
	{prefix: "evidence_", why: reasonOpensAStore},
	{prefix: "review_", why: reasonOpensAStore},
	{prefix: "retention_", why: reasonOpensAStore},
	{prefix: "erasure_", why: reasonOpensAStore},
	{prefix: "audit_", why: reasonOpensAStore},
	{prefix: "view_", why: reasonOpensAStore},
	{prefix: "disclose_", why: reasonOpensAStore},
	{prefix: "role_", why: reasonOpensAStore},
	{prefix: "redaction_", why: reasonOpensAStore},
	{prefix: "ntfs_", why: reasonOpensAnImage},
	{prefix: "fat_", why: reasonOpensAnImage},
	{prefix: "xfat_", why: reasonOpensAnImage},
	{prefix: "ext_", why: reasonOpensAnImage},
	{prefix: "hfs_", why: reasonOpensAnImage},
	{prefix: "xfs_", why: reasonOpensAnImage},
	{prefix: "mft_", why: reasonOpensAnImage},
	{prefix: "vhdi_", why: reasonOpensAnImage},
	{prefix: "ewf_", why: reasonOpensAnImage},
	{prefix: "raw_", why: reasonOpensAnImage},
	{prefix: "table_", why: reasonOpensAnImage},
	{prefix: "reg_", why: reasonOpensAPath},
	{prefix: "hive_", why: reasonOpensAPath},
	{prefix: "amcache_", why: reasonOpensAPath},
	{prefix: "shimcache_", why: reasonOpensAPath},
	{prefix: "prefetch_", why: reasonOpensAPath},
	{prefix: "evtx_", why: reasonOpensAPath},
	{prefix: "lnk_", why: reasonOpensAPath},
	{prefix: "jumplist_", why: reasonOpensAPath},
	{prefix: "sqlite_", why: reasonOpensAPath},
	{prefix: "browser_", why: reasonOpensAPath},
	{prefix: "email_", why: reasonOpensAPath},
	{prefix: "syslog_", why: reasonOpensAPath},
	{prefix: "zip_", why: reasonOpensAPath},
	{prefix: "tar_", why: reasonOpensAPath},
	{prefix: "bin_", why: reasonOpensAPath},
	{prefix: "go_", why: reasonOpensAPath},
	{prefix: "detect_", why: reasonOpensAPath},
	{prefix: "sigma_", why: reasonOpensAPath},
	{prefix: "hashset_", why: reasonOpensAPath},
	{prefix: "report_", why: reasonOpensAPath},
	{prefix: "test", why: reasonNoTestRun},
	{prefix: "before_each", why: reasonNoTestRun},
	{prefix: "after_each", why: reasonNoTestRun},
	{prefix: "assert", why: reasonNoTestRun},
	{prefix: "fail", why: reasonNoTestRun},
}

// MacroSafe reports whether a macro body may call this builtin while the
// compiler is running. Anything it was not told about is refused.
func MacroSafe(name string) bool {
	return slices.Contains(macroSafeBuiltins, name)
}

// MacroSafeBuiltins is macroSafeBuiltins, for the editor and for gendocs.
func MacroSafeBuiltins() []string { return slices.Clone(macroSafeBuiltins) }

// MacroRefusal is the reason this builtin is not available during macro
// expansion, or "" when it is. It never answers with an empty reason for a
// refused name: a name no rule matches gets the general one, so the expander
// always has a sentence to print.
func MacroRefusal(name string) string {
	if MacroSafe(name) {
		return ""
	}
	for _, rule := range macroRefusals {
		if rule.name != "" && rule.name == name {
			return rule.why
		}
		if rule.prefix != "" && strings.HasPrefix(name, rule.prefix) {
			return rule.why
		}
	}
	return reasonPureComputation
}

// MacroUnclassified is every registered builtin that is neither allowed nor
// named by a refusal rule -- so nobody has decided about it. The drift guard
// fails while this is non-empty, which is what forces a new builtin to be
// classified before it ships.
func MacroUnclassified() []string {
	var unclassified []string
	for _, def := range Builtins {
		if def.Name == "" || MacroSafe(def.Name) {
			continue
		}
		if macroRefusalRule(def.Name) < 0 {
			unclassified = append(unclassified, def.Name)
		}
	}
	slices.Sort(unclassified)
	return slices.Compact(unclassified)
}

// macroRefusalRule is the index of the rule that answers for this name, or -1
// when no rule does. It exists so MacroUnclassified can tell "no rule matched"
// apart from "a rule matched and gave the general reason", which MacroRefusal
// deliberately cannot.
func macroRefusalRule(name string) int {
	for i, rule := range macroRefusals {
		if rule.name != "" && rule.name == name {
			return i
		}
		if rule.prefix != "" && strings.HasPrefix(name, rule.prefix) {
			return i
		}
	}
	return -1
}
