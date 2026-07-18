package builtin

import "strings"

type BuiltinParamDoc struct {
	Name string
	Doc  string
}

type builtinFamilyDoc struct {
	prefix  string
	summary string
}

type builtinDoc struct {
	signature string
	summary   string
	params    []builtinParamDoc
}

type builtinParamDoc struct {
	name string
	doc  string
}

var builtinDocs = map[string]builtinDoc{
	BuiltinNameLen: {
		signature: "len(value)",
		summary:   "Returns the length of a string, array, hash, or bytes value.",
		params:    []builtinParamDoc{{name: "value", doc: "String, array, hash, or bytes value to measure."}},
	},
	BuiltinNamePutln: {signature: "putln(value)", summary: "Prints a value followed by a newline."},
	BuiltinNamePutf: {
		signature: "putf(format, ...values)",
		summary:   "Formats and prints values using a format string.",
		params: []builtinParamDoc{
			{name: "format", doc: "Printf-style format string."},
			{name: "...values", doc: "Values interpolated into format."},
		},
	},
	BuiltinNameGets:          {signature: "gets()", summary: "Reads a line of input from stdin."},
	BuiltinNameFirst:         {signature: "first(array)", summary: "Returns the first element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	BuiltinNameLast:          {signature: "last(array)", summary: "Returns the last element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	BuiltinNameRest:          {signature: "rest(array)", summary: "Returns a new array without the first element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	BuiltinNamePush:          {signature: "push(array, value)", summary: "Returns a new array with value appended.", params: []builtinParamDoc{{name: "array", doc: "Source array."}, {name: "value", doc: "Element to append."}}},
	BuiltinNamePop:           {signature: "pop(array)", summary: "Returns a new array without the last element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	BuiltinNameFsRead:        {signature: "fs_read(path)", summary: "Reads file contents from disk.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}}},
	BuiltinNameFsWrite:       {signature: "fs_write(path, data)", summary: "Writes data to a file, replacing existing contents.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	BuiltinNameFsAppend:      {signature: "fs_append(path, data)", summary: "Appends data to the end of a file.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	BuiltinNameFsExists:      {signature: "fs_exists(path)", summary: "Returns whether a file or directory exists.", params: []builtinParamDoc{{name: "path", doc: "Path to check."}}},
	BuiltinNameHttpGet:       {signature: "http_get(url)", summary: "Performs an HTTP GET request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}}},
	BuiltinNameHttpPost:      {signature: "http_post(url, body)", summary: "Performs an HTTP POST request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}, {name: "body", doc: "Request body value."}}},
	BuiltinNameHttpRequest:   {signature: "http_request(method, url, opts)", summary: "Performs a configurable HTTP request.", params: []builtinParamDoc{{name: "method", doc: "HTTP verb (GET/POST/etc)."}, {name: "url", doc: "Absolute request URL."}, {name: "opts", doc: "Headers/body/timeout options."}}},
	BuiltinNameJsonParse:     {signature: "json_parse(text)", summary: "Parses JSON text into Mutant values.", params: []builtinParamDoc{{name: "text", doc: "JSON string input."}}},
	BuiltinNameJsonStringify: {signature: "json_stringify(value)", summary: "Serializes Mutant values into JSON text.", params: []builtinParamDoc{{name: "value", doc: "Value to serialize."}}},
	BuiltinNameLuaRunString:  {signature: "lua_run_string(code)", summary: "Runs a Lua script from a string."},
	BuiltinNameLuaRunFile:    {signature: "lua_run_file(path)", summary: "Runs a Lua script from a file."},
	BuiltinNameLuaRunHttp:    {signature: "lua_run_http(url)", summary: "Fetches and runs a Lua script from an HTTP endpoint."},
	BuiltinNameTextContains:  {signature: "text_contains(haystack, needle)", summary: "Returns whether a string contains a substring."},
	BuiltinNameTextIndex:     {signature: "text_index(haystack, needle)", summary: "Returns the first index of substring occurrence, or -1."},
	BuiltinNameTextCount:     {signature: "text_count(haystack, needle)", summary: "Counts non-overlapping substring occurrences."},
	BuiltinNameTextSplit:     {signature: "text_split(text, sep)", summary: "Splits text by separator and returns an array of parts."},
	BuiltinNameTextReplace:   {signature: "text_replace(text, old, new)", summary: "Replaces substring occurrences in text."},
	BuiltinNameTextLevenshtein: {
		signature: "text_levenshtein(left, right)",
		summary:   "Computes Levenshtein edit distance between two strings.",
	},
	BuiltinNameTextSimilarity: {
		signature: "text_similarity(left, right)",
		summary:   "Computes normalized Levenshtein similarity between two strings.",
		params: []builtinParamDoc{
			{name: "left", doc: "First string to compare."},
			{name: "right", doc: "Second string to compare."},
		},
	},
	BuiltinNameTextFuzzyFind: {
		signature: "text_fuzzy_find(query, candidates, maxDistance?)",
		summary:   "Finds the closest fuzzy match in an array of candidate strings.",
	},
	BuiltinNameTextJaroWinkler: {
		signature: "text_jaro_winkler(left, right)",
		summary:   "Computes Jaro-Winkler string similarity score.",
	},
	BuiltinNameRegexMatch: {signature: "regex_match(pattern, input)", summary: "Returns whether regex pattern matches input."},
	BuiltinNameRegexFind:  {signature: "regex_find(pattern, input)", summary: "Finds the first regex match in input."},
	BuiltinNameRegexFindAll: {
		signature: "regex_find_all(pattern, input, limit?)",
		summary:   "Finds all regex matches with optional result limit.",
	},
	BuiltinNameRegexReplace: {
		signature: "regex_replace(pattern, input, replacement)",
		summary:   "Replaces all regex matches in input with replacement text.",
		params: []builtinParamDoc{
			{name: "pattern", doc: "Regular expression pattern."},
			{name: "input", doc: "Input string to transform."},
			{name: "replacement", doc: "Replacement text for each match."},
		},
	},
	BuiltinNameRegexCaptureGroups: {
		signature: "regex_capture_groups(pattern, input)",
		summary:   "Returns full regex capture array (full match plus groups).",
	},
	BuiltinNamePolicyLoad: {
		signature: "policy_load(name, source)",
		summary:   "Loads a policy module by name from source text or config hash.",
	},
	BuiltinNamePolicyEval: {
		signature: "policy_eval(policy, input)",
		summary:   "Evaluates a loaded policy and returns decision details.",
		params: []builtinParamDoc{
			{name: "policy", doc: "Policy name or handle."},
			{name: "input", doc: "Input data evaluated by the policy."},
		},
	},
	BuiltinNamePolicyAllow: {
		signature: "policy_allow(policy, input)",
		summary:   "Evaluates and returns allow/deny boolean for a policy.",
	},
	BuiltinNamePolicyRules: {
		signature: "policy_rules(policy)",
		summary:   "Returns rule metadata exported by a loaded policy.",
	},
	BuiltinNamePolicyTrace: {
		signature: "policy_trace(policy, input)",
		summary:   "Runs policy evaluation with trace output for debugging rule flow.",
		params: []builtinParamDoc{
			{name: "policy", doc: "Policy name or handle."},
			{name: "input", doc: "Input data evaluated by the policy."},
		},
	},
	BuiltinNameCacheOpen: {
		signature: "cache_open(name)",
		summary:   "Opens or creates a named in-memory cache store.",
		params:    []builtinParamDoc{{name: "name", doc: "Cache namespace identifier."}},
	},
	BuiltinNameCachePut: {
		signature: "cache_put(name, key, value, ttlSeconds?)",
		summary:   "Stores a value in a named cache key with optional TTL.",
		params: []builtinParamDoc{
			{name: "name", doc: "Cache namespace identifier."},
			{name: "key", doc: "Cache key string."},
			{name: "value", doc: "Value to store."},
			{name: "ttlSeconds?", doc: "Optional expiration in seconds (0 for no expiry)."},
		},
	},
	BuiltinNameCacheGet: {
		signature: "cache_get(name, key)",
		summary:   "Reads a value from cache and returns found/value fields.",
		params: []builtinParamDoc{
			{name: "name", doc: "Cache namespace identifier."},
			{name: "key", doc: "Cache key string."},
		},
	},
	BuiltinNameCacheDelete: {
		signature: "cache_delete(name, key)",
		summary:   "Deletes a key from cache and returns whether it existed.",
	},
	BuiltinNameCacheKeys: {
		signature: "cache_keys(name)",
		summary:   "Lists sorted cache keys for a cache namespace.",
	},
	BuiltinNameCacheStats: {
		signature: "cache_stats(name)",
		summary:   "Returns cache counters such as hits, misses, puts, deletes, and expires.",
		params:    []builtinParamDoc{{name: "name", doc: "Cache namespace identifier."}},
	},
	BuiltinNameCacheClear: {
		signature: "cache_clear(name)",
		summary:   "Clears all entries and resets relevant cache state.",
	},
	BuiltinNameProcessList: {signature: "process_list()", summary: "Lists visible processes with pid, ppid, and executable name."},
	BuiltinNameProcessTree: {
		signature: "process_tree(rootPid?)",
		summary:   "Returns descendant processes for a root pid (default current process).",
		params:    []builtinParamDoc{{name: "rootPid?", doc: "Optional root process ID; defaults to current process."}},
	},
	BuiltinNameProcessOpenFiles: {
		signature: "process_open_files(pid?)",
		summary:   "Lists open file paths for a process (platform dependent).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessThreads: {
		signature: "process_threads(pid?)",
		summary:   "Lists thread IDs for a process (platform dependent).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessModules: {
		signature: "process_modules(pid?)",
		summary:   "Lists loaded module/library paths for a process.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessHash: {
		signature: "process_hash(pid?)",
		summary:   "Computes SHA-256 hash metadata for a process executable.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessMemoryScan: {
		signature: "process_memory_scan(pid, pattern)",
		summary:   "Scans process memory for a string pattern (advisory/stub on some platforms).",
		params: []builtinParamDoc{
			{name: "pid", doc: "Target process ID to scan."},
			{name: "pattern", doc: "String pattern searched in process memory."},
		},
	},
	BuiltinNameProcessEnv: {
		signature: "process_env(pid?)",
		summary:   "Returns environment variables for a process.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessKill: {
		signature: "process_kill(pid, signal?)",
		summary:   "Sends a signal to a process (default SIGKILL semantics).",
		params: []builtinParamDoc{
			{name: "pid", doc: "Target process ID."},
			{name: "signal?", doc: "Optional integer signal number."},
		},
	},
	BuiltinNameExecString: {
		signature: "exec_string(command, shell?)",
		summary:   "Executes a shell command string via security-guarded command execution.",
		params: []builtinParamDoc{
			{name: "command", doc: "Command text to execute."},
			{name: "shell?", doc: "Optional shell executable (defaults to powershell)."},
		},
	},
	BuiltinNameCmdBuilder: {
		signature: "cmd_builder(shell?)",
		summary:   "Creates a command builder object for step-wise command composition.",
		params:    []builtinParamDoc{{name: "shell?", doc: "Optional shell executable (defaults to powershell)."}},
	},
	BuiltinNameCmdAdd: {
		signature: "cmd_add(builder, arg)",
		summary:   "Appends an argument to a command builder.",
		params: []builtinParamDoc{
			{name: "builder", doc: "Builder hash returned by cmd_builder/cmd_add."},
			{name: "arg", doc: "Command line text appended as a new line."},
		},
	},
	BuiltinNameCmdRun: {
		signature: "cmd_run(builder)",
		summary:   "Executes a composed command and returns run output metadata.",
		params:    []builtinParamDoc{{name: "builder", doc: "Builder hash containing shell and command lines."}},
	},
	BuiltinNameFsDelete: {signature: "fs_delete(path)", summary: "Deletes a file from disk."},
	BuiltinNameFsStat:   {signature: "fs_stat(path)", summary: "Returns file metadata such as size and timestamps."},
	BuiltinNameFsList:   {signature: "fs_list(path)", summary: "Lists directory entries for a path."},
	BuiltinNameFsMkdir:  {signature: "fs_mkdir(path)", summary: "Creates a directory path."},
	BuiltinNameFsCopy:   {signature: "fs_copy(src, dst)", summary: "Copies a file from source path to destination path."},
	BuiltinNameFsMove:   {signature: "fs_move(src, dst)", summary: "Moves or renames a file or directory."},
	BuiltinNameFsHash:   {signature: "fs_hash(path)", summary: "Computes hash digests for a file."},
	BuiltinNameFsWalk:   {signature: "fs_walk(root)", summary: "Walks a directory tree and returns discovered paths."},
	BuiltinNameFsMetadata: {
		signature: "fs_metadata(path)",
		summary:   "Returns detailed filesystem metadata for a path.",
	},
	BuiltinNameFsMagic: {
		signature: "fs_magic(path)",
		summary:   "Infers file type/magic information from file contents.",
	},
	BuiltinNameFsExtractStrings: {
		signature: "fs_extract_strings(path, minLen?)",
		summary:   "Extracts printable strings from a file.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to source file."},
			{name: "minLen?", doc: "Optional minimum string length (default 4)."},
		},
	},
	BuiltinNameFsDiff: {
		signature: "fs_diff(leftPath, rightPath)",
		summary:   "Compares two files or directories and reports differences.",
	},
	BuiltinNameFsCarve: {
		signature: "fs_carve(path, type)",
		summary:   "Carves matching binary artifacts from a file by known artifact type.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to source file."},
			{name: "type", doc: "Artifact type signature such as pe/elf/pdf/zip."},
		},
	},
	BuiltinNameFsEntropy: {
		signature: "fs_entropy(path)",
		summary:   "Computes file entropy for packed/encrypted artifact detection.",
	},
	BuiltinNameBinPeParse: {
		signature: "bin_pe_parse(path)",
		summary:   "Parses PE headers and returns core binary metadata.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to PE file."}},
	},
	BuiltinNameBinElfParse: {
		signature: "bin_elf_parse(path)",
		summary:   "Parses ELF headers and returns core binary metadata.",
	},
	BuiltinNameBinDwarfParse: {
		signature: "bin_dwarf_parse(path)",
		summary:   "Parses DWARF metadata and reports compile unit information.",
	},
	BuiltinNameBinStrings: {
		signature: "bin_strings(path, minLen?)",
		summary:   "Extracts printable strings from a binary.",
	},
	BuiltinNameBinEntropy: {
		signature: "bin_entropy(path)",
		summary:   "Computes binary entropy signal.",
	},
	BuiltinNameBinYaraScan: {
		signature: "bin_yara_scan(path, rules)",
		summary:   "Runs YARA-like signature scanning on a binary.",
	},
	BuiltinNameBinImports: {
		signature: "bin_imports(path)",
		summary:   "Returns imported symbols/libraries from a binary.",
	},
	BuiltinNameBinSections: {
		signature: "bin_sections(path)",
		summary:   "Returns binary section table information.",
	},
	BuiltinNameNetSynScan: {signature: "net_syn_scan(target, ports)", summary: "Performs TCP SYN scanning for target ports."},
	BuiltinNameNetUdpScan: {signature: "net_udp_scan(target, ports)", summary: "Performs UDP scanning for target ports."},
	BuiltinNameNetBanner:  {signature: "net_banner(address)", summary: "Collects service banner text from a network endpoint."},
	BuiltinNameNetTlsFingerprint: {
		signature: "net_tls_fingerprint(address, timeoutMs)",
		summary:   "Collects TLS certificate and handshake fingerprint metadata.",
		params: []builtinParamDoc{
			{name: "address", doc: "Host:port endpoint for TLS connection."},
			{name: "timeoutMs", doc: "Dial timeout in milliseconds."},
		},
	},
	BuiltinNameNetDnsQuery: {
		signature: "net_dns_query(name, qtype)",
		summary:   "Queries DNS records for a hostname.",
		params: []builtinParamDoc{
			{name: "name", doc: "DNS name or reverse-lookup value."},
			{name: "qtype", doc: "Query type: A, AAAA, IP, CNAME, MX, TXT, NS, or PTR."},
		},
	},
	BuiltinNameNetPcapAnalyze: {
		signature: "net_pcap_analyze(path)",
		summary:   "Analyzes PCAP captures and returns flow/session signals.",
	},
	BuiltinNameNetCaptureRaw: {
		signature: "net_capture_raw()",
		summary:   "Captures raw packets from an interface for a time window.",
	},
	BuiltinNameNetFlowReconstruct: {
		signature: "net_flow_reconstruct(packets)",
		summary:   "Reconstructs higher-level flows from packet records.",
		params:    []builtinParamDoc{{name: "packets", doc: "Array of packet hashes with src/dst/ports/protocol/bytes fields."}},
	},
	BuiltinNameNetOsFingerprint: {
		signature: "net_os_fingerprint(target, timeoutMs)",
		summary:   "Infers probable remote OS fingerprint from network responses.",
		params: []builtinParamDoc{
			{name: "target", doc: "Target host or address."},
			{name: "timeoutMs", doc: "Probe timeout in milliseconds."},
		},
	},
	BuiltinNameRegOpen: {
		signature: "reg_open(path)",
		summary:   "Opens a registry hive data source and returns a handle.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to hive JSON file."}},
	},
	BuiltinNameRegEnumKeys: {
		signature: "reg_enum_keys(hiveHandle, keyPath)",
		summary:   "Enumerates subkeys under a registry path.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path to enumerate."},
		},
	},
	BuiltinNameRegEnumValues: {
		signature: "reg_enum_values(hiveHandle, keyPath)",
		summary:   "Enumerates values under a registry path.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path to enumerate."},
		},
	},
	BuiltinNameRegGetValue: {
		signature: "reg_get_value(hiveHandle, keyPath, valueName)",
		summary:   "Reads a specific registry value with type metadata.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path that contains the value."},
			{name: "valueName", doc: "Registry value name to fetch."},
		},
	},
	BuiltinNameRegDeletedKeys: {
		signature: "reg_deleted_keys(hiveHandle)",
		summary:   "Lists deleted keys recovered from hive artifacts.",
	},
	BuiltinNameRegTimeline: {
		signature: "reg_timeline(hiveHandle)",
		summary:   "Returns timeline events extracted from an opened registry hive.",
		params:    []builtinParamDoc{{name: "hiveHandle", doc: "Handle returned by reg_open."}},
	},
	BuiltinNameEmailParse: {
		signature: "email_parse(raw)",
		summary:   "Parses a raw email message into headers, body parts, and attachments.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameEmailHeaders: {
		signature: "email_headers(raw)",
		summary:   "Parses and returns message headers from raw email input.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameEmailAttachments: {
		signature: "email_attachments(raw)",
		summary:   "Extracts attachment metadata/content details from raw email input.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameEmailSpfDkim: {
		signature: "email_spf_dkim(raw)",
		summary:   "Evaluates SPF/DKIM/DMARC signals from message headers.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameEmailUrls: {
		signature: "email_urls(raw)",
		summary:   "Extracts and normalizes URLs from email headers and body.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameMemMap: {
		signature: "mem_map(path)",
		summary:   "Builds memory map segments from a memory dump file.",
	},
	BuiltinNameMemRead: {
		signature: "mem_read(path, offset, size)",
		summary:   "Reads a byte range from a memory image.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "offset", doc: "Starting offset in bytes."},
			{name: "size", doc: "Number of bytes to read."},
		},
	},
	BuiltinNameMemScan: {
		signature: "mem_scan(path, pattern)",
		summary:   "Scans a memory image for a string/byte pattern.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "pattern", doc: "String pattern to search for."},
		},
	},
	BuiltinNameMemStrings: {
		signature: "mem_strings(path, minLen?)",
		summary:   "Extracts printable strings from memory image data.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "minLen?", doc: "Optional minimum string length (default 4)."},
		},
	},
	BuiltinNameMemFindPe: {
		signature: "mem_find_pe(path)",
		summary:   "Finds PE header offsets in memory image data.",
	},
	BuiltinNameMemFindShellcode: {
		signature: "mem_find_shellcode(path)",
		summary:   "Scans a memory dump file for common shellcode byte signatures.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to memory image or dump file."}},
	},
	BuiltinNameDetectPersistence: {
		signature: "detect_persistence(facts)",
		summary:   "Detects persistence indicators from host evidence facts.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash containing autorun/startup/task evidence."}},
	},
	BuiltinNameDetectInjection: {
		signature: "detect_injection(facts)",
		summary:   "Detects probable code injection signals from memory-derived evidence.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash containing evidence such as mem_path."}},
	},
	BuiltinNameDetectNetworkBeacon: {
		signature: "detect_network_beacon(flows)",
		summary:   "Detects beacon-like repeated outbound network destinations.",
		params:    []builtinParamDoc{{name: "flows", doc: "Array of flow hashes that include destination endpoint data."}},
	},
	BuiltinNameDetectPrivEsc: {
		signature: "detect_priv_esc(facts)",
		summary:   "Detects potential privilege-escalation indicators from host facts.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash of privilege-related evidence and boolean checks."}},
	},
	BuiltinNameDetectSuspiciousFiles: {
		signature: "detect_suspicious_files(paths)",
		summary:   "Detects suspicious file artifacts using extension/path heuristics.",
		params:    []builtinParamDoc{{name: "paths", doc: "Array of filesystem paths to inspect."}},
	},
	BuiltinNameNetResolve:        {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses."},
	BuiltinNameNetDial:           {signature: "net_dial(address)", summary: "Opens a network connection."},
	BuiltinNameDbOpen:            {signature: "db_open()", summary: "Creates an in-memory graph database handle."},
	BuiltinNameDbOpenDisk:        {signature: "db_open_disk(path)", summary: "Opens or creates a disk-backed graph database.", params: []builtinParamDoc{{name: "path", doc: "Database file path."}}},
	BuiltinNameDbClose:           {signature: "db_close(db)", summary: "Closes a graph database handle and flushes pending state.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameDbAddNode:         {signature: "db_add_node(db, label, props)", summary: "Adds a node to the graph database.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "label", doc: "Node label/category."}, {name: "props", doc: "Node properties hash."}}},
	BuiltinNameDbAddEdge:         {signature: "db_add_edge(db, from, to, label, props)", summary: "Adds an edge between graph nodes.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}, {name: "label", doc: "Edge label/type."}, {name: "props", doc: "Edge properties hash."}}},
	BuiltinNameDbAddArtifact:     {signature: "db_add_artifact(db, artifact)", summary: "Adds a forensic artifact entity to the graph.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "artifact", doc: "Artifact hash payload."}}},
	BuiltinNameDbAddRelation:     {signature: "db_add_relation(db, from, to, relation, props?)", summary: "Adds a named relation edge between entities.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source entity ID."}, {name: "to", doc: "Destination entity ID."}, {name: "relation", doc: "Relation type string."}, {name: "props?", doc: "Optional relation properties hash."}}},
	BuiltinNameDbIndexProp:       {signature: "db_index_prop(db, key)", summary: "Builds or updates an index on a property key.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "key", doc: "Property key to index."}}},
	BuiltinNameDbQueryNodes:      {signature: "db_query_nodes(db, filter)", summary: "Queries nodes by label/properties filter.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "filter", doc: "Filter hash or query object."}}},
	BuiltinNameDbQuery:           {signature: "db_query(db, query)", summary: "Executes a graph query expression and returns results.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "query", doc: "Query expression string."}}},
	BuiltinNameDbBfs:             {signature: "db_bfs(db, start, maxDepth?)", summary: "Performs breadth-first graph traversal from a start node.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "start", doc: "Start node ID."}, {name: "maxDepth?", doc: "Optional traversal depth limit."}}},
	BuiltinNameDbShortestPath:    {signature: "db_shortest_path(db, from, to)", summary: "Computes shortest path between two graph nodes.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}}},
	BuiltinNameDbTimeline:        {signature: "db_timeline(db, opts?)", summary: "Builds chronological timeline views from graph evidence.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "opts?", doc: "Optional timeline filtering options."}}},
	BuiltinNameDbStats:           {signature: "db_stats(db)", summary: "Returns graph database statistics.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameBytesLen:          {signature: "bytes_len(data)", summary: "Returns length of a bytes value."},
	BuiltinNameBytesGet:          {signature: "bytes_get(data, index)", summary: "Reads one byte at index as integer."},
	BuiltinNameBytesSlice:        {signature: "bytes_slice(data, start, end)", summary: "Returns byte sub-slice from start to end."},
	BuiltinNameBytesHex:          {signature: "bytes_hex(data)", summary: "Returns uppercase hexadecimal representation of bytes."},
	BuiltinNameBytesCstrAt:       {signature: "bytes_cstr_at(data, offset)", summary: "Reads null-terminated string from bytes at offset."},
	BuiltinNameBytesCharFromInt:  {signature: "bytes_char_from_int(value)", summary: "Converts an integer byte value to a single-character string."},
	BuiltinNameBytesIntFromChar:  {signature: "bytes_int_from_char(char)", summary: "Converts a single-character string to its integer byte value."},
	BuiltinNameBytesReadU16Le:    {signature: "bytes_read_u16_le(data, offset)", summary: "Reads unsigned 16-bit little-endian integer from bytes at offset."},
	BuiltinNameBytesReadU16Be:    {signature: "bytes_read_u16_be(data, offset)", summary: "Reads unsigned 16-bit big-endian integer from bytes at offset."},
	BuiltinNameBytesReadU32Le:    {signature: "bytes_read_u32_le(data, offset)", summary: "Reads unsigned 32-bit little-endian integer from bytes at offset."},
	BuiltinNameBytesReadU32Be:    {signature: "bytes_read_u32_be(data, offset)", summary: "Reads unsigned 32-bit big-endian integer from bytes at offset."},
	BuiltinNameBytesReadU64Le:    {signature: "bytes_read_u64_le(data, offset)", summary: "Reads unsigned 64-bit little-endian integer from bytes at offset."},
	BuiltinNameBytesReadU64Be:    {signature: "bytes_read_u64_be(data, offset)", summary: "Reads unsigned 64-bit big-endian integer from bytes at offset."},
	BuiltinNameBytesWriteU16Le:   {signature: "bytes_write_u16_le(data, offset, value)", summary: "Writes unsigned 16-bit little-endian integer into bytes at offset."},
	BuiltinNameBytesWriteU16Be:   {signature: "bytes_write_u16_be(data, offset, value)", summary: "Writes unsigned 16-bit big-endian integer into bytes at offset."},
	BuiltinNameBytesWriteU32Le:   {signature: "bytes_write_u32_le(data, offset, value)", summary: "Writes unsigned 32-bit little-endian integer into bytes at offset."},
	BuiltinNameBytesWriteU32Be:   {signature: "bytes_write_u32_be(data, offset, value)", summary: "Writes unsigned 32-bit big-endian integer into bytes at offset."},
	BuiltinNameBytesWriteU64Le:   {signature: "bytes_write_u64_le(data, offset, value)", summary: "Writes unsigned 64-bit little-endian integer into bytes at offset."},
	BuiltinNameBytesWriteU64Be:   {signature: "bytes_write_u64_be(data, offset, value)", summary: "Writes unsigned 64-bit big-endian integer into bytes at offset."},
	BuiltinNameBytesCursorNew:    {signature: "bytes_cursor_new(data)", summary: "Creates a cursor for structured byte parsing."},
	BuiltinNameBytesCursorTell:   {signature: "bytes_cursor_tell(cursor)", summary: "Returns current cursor position."},
	BuiltinNameBytesCursorSeek:   {signature: "bytes_cursor_seek(cursor, offset)", summary: "Moves cursor to an absolute offset."},
	BuiltinNameBytesCursorEof:    {signature: "bytes_cursor_eof(cursor)", summary: "Returns whether cursor is at end-of-buffer."},
	BuiltinNameBytesCursorReadU8: {signature: "bytes_cursor_read_u8(cursor)", summary: "Reads one unsigned byte from cursor."},
	BuiltinNameBytesCursorReadU16Le: {
		signature: "bytes_cursor_read_u16_le(cursor)",
		summary:   "Reads unsigned 16-bit little-endian integer from cursor.",
	},
	BuiltinNameBytesCursorReadU16Be: {
		signature: "bytes_cursor_read_u16_be(cursor)",
		summary:   "Reads unsigned 16-bit big-endian integer from cursor.",
	},
	BuiltinNameBytesCursorReadU32Le: {
		signature: "bytes_cursor_read_u32_le(cursor)",
		summary:   "Reads unsigned 32-bit little-endian integer from cursor.",
	},
	BuiltinNameBytesCursorReadU32Be: {
		signature: "bytes_cursor_read_u32_be(cursor)",
		summary:   "Reads unsigned 32-bit big-endian integer from cursor.",
	},
	BuiltinNameBytesCursorReadU64Le: {
		signature: "bytes_cursor_read_u64_le(cursor)",
		summary:   "Reads unsigned 64-bit little-endian integer from cursor.",
	},
	BuiltinNameBytesCursorReadU64Be: {
		signature: "bytes_cursor_read_u64_be(cursor)",
		summary:   "Reads unsigned 64-bit big-endian integer from cursor.",
	},
	BuiltinNameSecurityDiagnostics: {signature: "security_diagnostics()", summary: "Returns security diagnostics for the current runtime."},
	BuiltinNameSandboxStatus:       {signature: "sandbox_status()", summary: "Returns sandbox-detection status information."},
	BuiltinNameDebugStatus:         {signature: "debug_status()", summary: "Returns runtime/debugger status information."},
	// secure networking (dev-sec)
	BuiltinNameNetConnect: {
		signature: "net_connect(address, timeoutMs)",
		summary:   "Opens a persistent TCP connection and returns a connection handle.",
		params:    []builtinParamDoc{{name: "address", doc: "host:port endpoint."}, {name: "timeoutMs", doc: "Dial timeout in milliseconds."}},
	},
	BuiltinNameNetTlsConnect: {
		signature: "net_tls_connect(address, timeoutMs, options?)",
		summary:   "Opens a TLS (secure) client connection and returns a connection handle.",
		params: []builtinParamDoc{
			{name: "address", doc: "host:port endpoint."},
			{name: "timeoutMs", doc: "Dial timeout in milliseconds."},
			{name: "options?", doc: "Hash: server_name, insecure, alpn, min_version, ca_cert, client_cert, client_key."},
		},
	},
	BuiltinNameNetConnWrite: {
		signature: "net_conn_write(handle, data)",
		summary:   "Writes bytes to a connection and returns the number written.",
		params:    []builtinParamDoc{{name: "handle", doc: "Connection handle."}, {name: "data", doc: "Bytes to send (STRING)."}},
	},
	BuiltinNameNetConnRead: {
		signature: "net_conn_read(handle, maxBytes, timeoutMs)",
		summary:   "Reads up to maxBytes from a connection; returns {data, bytes, eof, error}.",
		params:    []builtinParamDoc{{name: "handle", doc: "Connection handle."}, {name: "maxBytes", doc: "Maximum bytes to read."}, {name: "timeoutMs", doc: "Read timeout in ms (0 = block)."}},
	},
	BuiltinNameNetConnClose: {signature: "net_conn_close(handle)", summary: "Closes a connection and releases its handle."},
	BuiltinNameNetConnInfo:  {signature: "net_conn_info(handle)", summary: "Returns addressing and negotiated TLS session details for a connection."},
	BuiltinNameNetListen:    {signature: "net_listen(address)", summary: "Opens a plain TCP listener and returns a listener handle."},
	BuiltinNameNetTlsListen: {
		signature: "net_tls_listen(address, certPem, keyPem, options?)",
		summary:   "Opens a TLS-terminating listener from a PEM cert/key pair.",
		params: []builtinParamDoc{
			{name: "address", doc: "host:port to bind."},
			{name: "certPem", doc: "Server certificate chain (PEM)."},
			{name: "keyPem", doc: "Server private key (PEM)."},
			{name: "options?", doc: "Hash: alpn, min_version, client_ca (mutual TLS)."},
		},
	},
	BuiltinNameNetAccept:      {signature: "net_accept(listener, timeoutMs)", summary: "Accepts one connection; returns {ok, handle, remote_addr, timeout, error}."},
	BuiltinNameNetListenClose: {signature: "net_listen_close(handle)", summary: "Closes a listener and releases its handle."},
	BuiltinNameNetTlsUpgradeServer: {
		signature: "net_tls_upgrade_server(handle, certPem, keyPem, options?)",
		summary:   "Upgrades an accepted connection to server-side TLS (completes a CONNECT intercept).",
		params: []builtinParamDoc{
			{name: "handle", doc: "Connection handle to upgrade."},
			{name: "certPem", doc: "Leaf certificate (PEM), e.g. issued by tls_sign_cert."},
			{name: "keyPem", doc: "Leaf private key (PEM)."},
			{name: "options?", doc: "Hash: alpn, min_version, handshake_timeout_ms, client_ca."},
		},
	},
	BuiltinNameNetTlsUpgradeClient: {
		signature: "net_tls_upgrade_client(handle, options?)",
		summary:   "Upgrades an open connection to client-side TLS (STARTTLS / upstream leg).",
		params: []builtinParamDoc{
			{name: "handle", doc: "Connection handle to upgrade."},
			{name: "options?", doc: "Hash: server_name, insecure, alpn, ca_cert, handshake_timeout_ms."},
		},
	},
	BuiltinNameTlsGenerateCa: {
		signature: "tls_generate_ca(options?)",
		summary:   "Creates a self-signed CA certificate and key; returns {cert_pem, key_pem, serial}.",
		params:    []builtinParamDoc{{name: "options?", doc: "Hash: common_name, organization, days."}},
	},
	BuiltinNameTlsGenerateCert: {
		signature: "tls_generate_cert(options?)",
		summary:   "Creates a self-signed leaf/server certificate and key.",
		params:    []builtinParamDoc{{name: "options?", doc: "Hash: common_name, organization, dns_names, ip_addresses, days."}},
	},
	BuiltinNameTlsSignCert: {
		signature: "tls_sign_cert(caCertPem, caKeyPem, options?)",
		summary:   "Issues a leaf certificate signed by a CA (per-host interception cert).",
		params: []builtinParamDoc{
			{name: "caCertPem", doc: "CA certificate (PEM)."},
			{name: "caKeyPem", doc: "CA private key (PEM)."},
			{name: "options?", doc: "Hash: common_name, dns_names, ip_addresses, days."},
		},
	},
	BuiltinNameHttpParseRequest:     {signature: "http_parse_request(raw)", summary: "Parses a raw HTTP request into {method, url, path, host, proto, query, headers, body}."},
	BuiltinNameHttpParseResponse:    {signature: "http_parse_response(raw)", summary: "Parses a raw HTTP response into {status, status_text, proto, headers, body}."},
	BuiltinNameHttpBuildRequest:     {signature: "http_build_request(request)", summary: "Serialises a request hash into HTTP wire bytes."},
	BuiltinNameHttpBuildResponse:    {signature: "http_build_response(response)", summary: "Serialises a response hash into HTTP wire bytes (adds Content-Length)."},
	BuiltinNameHttpConnReadRequest:  {signature: "http_conn_read_request(handle, timeoutMs)", summary: "Reads exactly one HTTP request from a connection handle."},
	BuiltinNameHttpConnReadResponse: {signature: "http_conn_read_response(handle, timeoutMs)", summary: "Reads exactly one HTTP response from a connection handle."},
}

var builtinFamilyDocs = []builtinFamilyDoc{
	{prefix: "bytes_", summary: "Bytes utility for reading/writing binary data."},
	{prefix: "db_", summary: "Graph database helper for nodes, edges, indexing, or traversal."},
	{prefix: "fs_", summary: "Filesystem helper for reading/writing/managing files and directories."},
	{prefix: "http_", summary: "HTTP helper for network requests."},
	{prefix: "net_", summary: "Network helper for address resolution, sockets, scanning, and capture analysis."},
	{prefix: "tls_", summary: "TLS certificate authority helper for generating and signing X.509 certificates."},
	{prefix: "cmd_", summary: "Command execution helper."},
	{prefix: "exec_", summary: "Execution helper for running script/code strings in controlled contexts."},
	{prefix: "json_", summary: "JSON serialization/parsing helper."},
	{prefix: "lua_", summary: "Lua execution helper."},
	{prefix: "text_", summary: "Text analysis and fuzzy matching helper."},
	{prefix: "regex_", summary: "Regular expression matching and extraction helper."},
	{prefix: "policy_", summary: "Policy evaluation and trace helper."},
	{prefix: "cache_", summary: "In-memory cache helper for open/get/put/delete/stats workflows."},
	{prefix: "process_", summary: "Process forensics helper for inspection, memory scanning, and control."},
	{prefix: "bin_", summary: "Binary analysis helper for PE/ELF/DWARF parsing, strings, and entropy/signature workflows."},
	{prefix: "reg_", summary: "Registry forensics helper for hives, keys, values, and timeline analysis."},
	{prefix: "email_", summary: "Email forensics helper for headers, attachments, URLs, and authentication signals."},
	{prefix: "mem_", summary: "Memory forensics helper for maps, scans, strings, and shellcode/PE discovery."},
	{prefix: "detect_", summary: "Detection helper for persistence, injection, beaconing, privilege escalation, and suspicious files."},
	{prefix: "ntfs_", summary: "NTFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "fat_", summary: "FAT filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "xfat_", summary: "exFAT filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "ext_", summary: "ext filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "hfs_", summary: "HFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "xfs_", summary: "XFS filesystem parser helper for file listing, metadata, and data extraction."},
	{prefix: "vhdi_", summary: "VHD image parser helper for metadata lookup and offset reads."},
	{prefix: "ewf_", summary: "EWF image parser helper for metadata lookup and offset reads."},
	{prefix: "raw_", summary: "Raw disk image helper for metadata lookup and offset reads."},
	{prefix: "table_", summary: "Partition table parser helper for table and partition metadata."},
}

func TeachingDoc(name string) (string, string, []BuiltinParamDoc, bool) {
	doc, ok := builtinDocs[name]
	if !ok {
		return "", "", nil, false
	}

	params := make([]BuiltinParamDoc, 0, len(doc.params))
	for _, p := range doc.params {
		params = append(params, BuiltinParamDoc{Name: p.name, Doc: p.doc})
	}

	return doc.signature, doc.summary, params, true
}

func TeachingFamilySummary(name string) (string, bool) {
	for _, family := range builtinFamilyDocs {
		if strings.HasPrefix(name, family.prefix) {
			return family.summary, true
		}
	}
	return "", false
}

func HasTeachingCoverage(name string) bool {
	if _, _, _, ok := TeachingDoc(name); ok {
		return true
	}
	_, ok := TeachingFamilySummary(name)
	return ok
}
