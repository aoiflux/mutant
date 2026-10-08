package policy

// LimitBudget lists the unnamed limits (rules L1-L9) and undocumented named
// limits (rule N1) each file may still hold, one entry per finding, written the
// way limitscan.Finding.Key writes it: the rule, the function the limit is in,
// and the expression as written. See policy/limitscan for the rules and
// docs/CONFIGURATION_POLICY.md for why a limit must be named.
//
// It was seeded from the tree on 2026-09-24 at 174 findings in 82 files, and it
// only shrinks: TestUnnamedLimitsStayWithinBudget fails on a finding the list
// does not hold and on an entry no finding answers to, so an entry comes out in
// the same change that names its limit, and naming one limit never makes room
// for another. A file absent from this map may hold none. The target is an
// empty map; whatever is still here when a release is cut has to be justified
// in that release's hardcoded-values report.
var LimitBudget = map[string][]string{
	"builtin/archive.go": {
		"N1 package level: maxDecompressionRatio = 1000",
		"N1 package level: maxDecompressedBytes = 1 << 30",
		"N1 package level: maxArchiveEntries = 1 << 20",
	},
	"builtin/binary_analysis.go": {
		"L7 BinStrings: int64(4)",
	},
	"builtin/bodyfile_builtins.go": {
		"L2 BodyfileParse: 4*1024*1024",
		"L1 BodyfileParse: 64*1024",
	},
	"builtin/channels.go": {
		"N1 package level: maxChannelCapacity = 1 << 20",
		"N1 package level: maxLiveChannels = 1024",
		"N1 package level: maxRetainedChannels = 4096",
	},
	"builtin/class.go": {
		"N1 package level: maxClassLabel = 64",
	},
	"builtin/classified.go": {
		"N1 package level: classifiedWalkDepth = 64",
	},
	"builtin/collections_builtins.go": {
		"L8 Range: 10_000_000",
	},
	"builtin/disclose.go": {
		"N1 package level: maxDiscloseManifest = 16 << 20",
		"N1 package level: maxDiscloseProof = 1 << 20",
		"L9 checkFiles: 1<<20",
	},
	"builtin/disclose_history.go": {
		"N1 package level: maxWithdrawalReason = 4096",
	},
	"builtin/disk_image_extents.go": {
		"N1 package level: vhdiMaxExtents = 20000",
		"N1 package level: vhdiMaxNodes = 4096",
		"N1 package level: vhdiMaxLineages = 256",
	},
	"builtin/disk_image_parsers.go": {
		"N1 package level: maxInMemoryReadBytes = 32 * 1024 * 1024",
		"L7 Metadata: 512",
	},
	"builtin/filesystem_deleted.go": {
		"N1 package level: fsDeletedMaxEntries = 10000",
	},
	"builtin/filesystem_journal.go": {
		"N1 package level: fsJournalMaxEntries = 50000",
		"N1 package level: fsJournalMaxCopies = 256",
		"N1 package level: extWarningCap = 256",
	},
	"builtin/filesystem_report.go": {
		"N1 package level: fsReportMaxFiles = 50000",
		"N1 package level: fsReportMaxFragments = 256",
		"N1 package level: fsReportMaxAnomalies = 1000",
	},
	"builtin/filesystem_slack.go": {
		"N1 package level: fsSlackMaxRanges = 4096",
		"N1 package level: fsSlackMaxRuns = 20000",
		"N1 package level: fsSlackMaxEntries = 10000",
	},
	"builtin/filesystem_verify.go": {
		"N1 package level: fsVerifyMaxFindings = 1000",
	},
	"builtin/filesystem_xattr.go": {
		"N1 package level: fsAttrMaxValueBytes = 4096",
		"N1 package level: fsAttrMaxAttributes = 4096",
		"N1 package level: fsAttrMaxStreams = 1024",
		"N1 package level: fsAttrMaxACEs = 4096",
		"N1 package level: fsAttrMaxDescriptors = 20000",
		"N1 package level: fsAttrMaxRanges = 4096",
		"N1 package level: fsAttrMaxReparseHex = 16 << 10",
	},
	"builtin/format_binary.go": {
		"N1 package level: maxCBORNesting = 64",
		"N1 package level: maxCBORElements = 1 << 20",
		"N1 package level: maxProtobufDepth = 32",
		"N1 package level: maxProtobufFields = 1 << 18",
		"N1 package level: maxDERDepth = 64",
		"N1 package level: maxDERNodes = 1 << 18",
	},
	"builtin/format_native.go": {
		"N1 package level: maxNativeDepth = 256",
		"N1 package level: maxNativeNodes = 1 << 22",
	},
	"builtin/format_text.go": {
		"N1 package level: maxXMLDepth = 256",
		"N1 package level: maxXMLNodes = 1 << 21",
		"N1 package level: maxNDJSONLine = 64 << 20",
		"L1 NdjsonParse: 64*1024",
	},
	"builtin/fs_forensics.go": {
		"L7 FsExtractStrings: int64(4)",
	},
	"builtin/fuzzy_matching.go": {
		"L9 TextFuzzyFind: 1<<62 - 1",
	},
	"builtin/hashset_builtins.go": {
		"L2 HashsetLoad: 8*1024*1024",
		"L1 HashsetLoad: 64*1024",
	},
	"builtin/hive_builtins.go": {
		"L4 collectSubkeyList: 32",
	},
	"builtin/ioc_builtins.go": {
		"L8 CIDRHosts: 1 << 20",
	},
	"builtin/jumplist_builtins.go": {
		"L4 parseAutomaticJumplist: 64<<20",
	},
	"builtin/ledger_read.go": {
		"N1 package level: ledgerPatternMinNodes = 2",
		"N1 package level: ledgerPatternMaxNodes = 20",
	},
	"builtin/ledger_redact.go": {
		"N1 package level: ledgerReasonLeakMin = 4",
	},
	"builtin/memory_forensics.go": {
		"L8 MemMap: 4096",
		"L7 MemStrings: int64(4)",
	},
	"builtin/mft_builtins.go": {
		"L4 reconstructMFTPaths: 256",
	},
	"builtin/net.go": {
		"L3 NetDNSQuery: 5*time.Second",
	},
	"builtin/plist_builtins.go": {
		"L4 parseObject: 100",
	},
	"builtin/prefetch_builtins.go": {
		"N1 package level: maxPrefetchDecompressed = 64 << 20",
	},
	"builtin/record.go": {
		"N1 package level: recordMaxRangesInArg = security.MaxRecordSpans",
	},
	"builtin/registry_forensics.go": {
		"L8 registryTypeName: 4294967295",
	},
	"builtin/report.go": {
		"N1 package level: reportMaxLevel = 6",
	},
	"builtin/secure_net.go": {
		"N1 package level: maxConnReadBytes = 32 << 20",
		"N1 package level: defaultWriteTimeoutMs = 30_000",
		"L3 TLSGenerateCA: -1 * time.Hour",
		"L3 leafTemplate: -1 * time.Hour",
	},
	"builtin/serve.go": {
		"N1 package level: maxServeHandlers = 1024",
	},
	"builtin/sigma_engine.go": {
		"L4 sigmaCollect: 24",
	},
	"builtin/sqlite_builtins.go": {
		"N1 package level: sqliteMaxRows = 1_000_000",
	},
	"builtin/syslog_builtins.go": {
		"L2 SyslogParse: 8*1024*1024",
		"L1 SyslogParse: 64*1024",
	},
	"builtin/system_forensics.go": {
		"L8 ProcessMemoryScan: 10000",
	},
	"builtin/system_forensics_memscan.go": {
		"N1 package level: memScanChunkSize = 4 << 20",
	},
	"builtin/system_forensics_memscan_linux.go": {
		"L2 sfScanSelfMemory: 1024*1024",
		"L1 sfScanSelfMemory: 64*1024",
	},
	"builtin/tasks.go": {
		"N1 package level: maxLiveTasks = 1024",
		"N1 package level: maxRetainedTasks = 4096",
	},
	"builtin/view.go": {
		"N1 package level: maxViewClasses = 256",
	},
	"builtin/websocket.go": {
		"L4 WSWriteFrame: 65536",
	},
	"cmd/sweep/main.go": {
		"L6 parseOptions: 60*time.Second",
		"L6 parseOptions: 3*time.Second",
		"L6 parseOptions: 424242",
	},
	"dap/transport.go": {
		"N1 package level: maxMessageBytes = 16 << 20",
	},
	"evaluator/macro_expansion.go": {
		"N1 package level: maxExpansionPasses = 100",
	},
	"global/const.go": {
		"N1 package level: StackSize = 2048",
		"N1 package level: GlobalSize = 65536",
	},
	"lsp/internal/analyzer/fn_solver.go": {
		"L5 solveFunctionParams: 8",
	},
	"lsp/internal/analyzer/hardcoded_secret.go": {
		"N1 package level: minimumSecretLength = 8",
	},
	"lsp/internal/analyzer/unbounded_resource.go": {
		"N1 package level: maxRangeLength = 10_000_000",
		"N1 package level: maxCIDRHostBits = 20",
	},
	"lsp/internal/server/range_formatter.go": {
		"N1 package level: maxDiffLines = 2000",
	},
	"lsp/internal/server/workspace_scan.go": {
		"N1 package level: scanMaxFiles = 5000",
		"N1 package level: scanMaxFileBytes = 1 << 20",
	},
	"lsp/internal/workspace/symbol_index.go": {
		"L7 WorkspaceSymbols: 100",
	},
	"main.go": {
		"N1 package level: defaultPolymorphicLevel = 5",
	},
	"object/secure_memory.go": {
		"L3 NewSecureStack: 100 * time.Millisecond",
	},
	"repl/repl.go": {
		"N1 package level: idleInterval = 30 * time.Second",
	},
	"runtime/lua/vm.go": {
		"L7 DefaultSandboxConfig: 64",
		"L7 DefaultSandboxConfig: 5000",
	},
	"security/antidebug_linux.go": {
		// M26-TMP-010 decides this one: the length check it sizes cannot run
		// while LD_PRELOAD counts as a debugger's marker by being set at all.
		"N1 package level: linuxLDPreloadLengthLimit = 50",
	},
	"vm/debugger.go": {
		"N1 package level: maxDebugValue = 256",
		"N1 package level: maxDebugChildren = 200",
	},
	"vm/parallel.go": {
		"N1 package level: maxParallelWorkers = 1024",
	},
	"vm/testing.go": {
		"N1 package level: testValueCap = 200",
	},
	"vm/traceback.go": {
		"N1 package level: maxRenderedArgValue = 48",
		"N1 package level: maxRenderedArgs = 6",
		"N1 package level: maxCycleLength = 8",
		"N1 package level: minCycleRepeats = 3",
		"N1 package level: maxRenderedFrames = 40",
	},
	"vm/vm.go": {
		"N1 package level: initialStackCapacity = global.StackSize",
		"N1 package level: initialGlobalsCapacity = global.GlobalSize",
		"N1 package level: initialFrameCapacity = 2048",
	},
}
