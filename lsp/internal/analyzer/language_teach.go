package analyzer

import (
	"fmt"
	"strings"

	"mutant/builtin"

	lsp "github.com/tliron/glsp/protocol_3_16"
)

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
	"len": {
		signature: "len(value)",
		summary:   "Returns the length of a string, array, hash, or bytes value.",
		params:    []builtinParamDoc{{name: "value", doc: "String, array, hash, or bytes value to measure."}},
	},
	"putln": {signature: "putln(value)", summary: "Prints a value followed by a newline."},
	"putf": {
		signature: "putf(format, ...values)",
		summary:   "Formats and prints values using a format string.",
		params: []builtinParamDoc{
			{name: "format", doc: "Printf-style format string."},
			{name: "...values", doc: "Values interpolated into format."},
		},
	},
	"gets":           {signature: "gets()", summary: "Reads a line of input from stdin."},
	"first":          {signature: "first(array)", summary: "Returns the first element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"last":           {signature: "last(array)", summary: "Returns the last element of an array.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"rest":           {signature: "rest(array)", summary: "Returns a new array without the first element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"push":           {signature: "push(array, value)", summary: "Returns a new array with value appended.", params: []builtinParamDoc{{name: "array", doc: "Source array."}, {name: "value", doc: "Element to append."}}},
	"pop":            {signature: "pop(array)", summary: "Returns a new array without the last element.", params: []builtinParamDoc{{name: "array", doc: "Source array."}}},
	"fs_read":        {signature: "fs_read(path)", summary: "Reads file contents from disk.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}}},
	"fs_write":       {signature: "fs_write(path, data)", summary: "Writes data to a file, replacing existing contents.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	"fs_append":      {signature: "fs_append(path, data)", summary: "Appends data to the end of a file.", params: []builtinParamDoc{{name: "path", doc: "Path to file."}, {name: "data", doc: "String/bytes payload."}}},
	"fs_exists":      {signature: "fs_exists(path)", summary: "Returns whether a file or directory exists.", params: []builtinParamDoc{{name: "path", doc: "Path to check."}}},
	"http_get":       {signature: "http_get(url)", summary: "Performs an HTTP GET request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}}},
	"http_post":      {signature: "http_post(url, body)", summary: "Performs an HTTP POST request.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}, {name: "body", doc: "Request body value."}}},
	"http_request":   {signature: "http_request(method, url, opts)", summary: "Performs a configurable HTTP request.", params: []builtinParamDoc{{name: "method", doc: "HTTP verb (GET/POST/etc)."}, {name: "url", doc: "Absolute request URL."}, {name: "opts", doc: "Headers/body/timeout options."}}},
	"json_parse":     {signature: "json_parse(text)", summary: "Parses JSON text into Mutant values.", params: []builtinParamDoc{{name: "text", doc: "JSON string input."}}},
	"json_stringify": {signature: "json_stringify(value)", summary: "Serializes Mutant values into JSON text.", params: []builtinParamDoc{{name: "value", doc: "Value to serialize."}}},
	"lua_run_string": {signature: "lua_run_string(code)", summary: "Runs a Lua script from a string."},
	"lua_run_file":   {signature: "lua_run_file(path)", summary: "Runs a Lua script from a file."},
	"lua_run_http":   {signature: "lua_run_http(url)", summary: "Fetches and runs a Lua script from an HTTP endpoint."},
	"text_contains":  {signature: "text_contains(haystack, needle)", summary: "Returns whether a string contains a substring."},
	"text_index":     {signature: "text_index(haystack, needle)", summary: "Returns the first index of substring occurrence, or -1."},
	"text_count":     {signature: "text_count(haystack, needle)", summary: "Counts non-overlapping substring occurrences."},
	"text_split":     {signature: "text_split(text, sep)", summary: "Splits text by separator and returns an array of parts."},
	"text_replace":   {signature: "text_replace(text, old, new)", summary: "Replaces substring occurrences in text."},
	"text_levenshtein": {
		signature: "text_levenshtein(left, right)",
		summary:   "Computes Levenshtein edit distance between two strings.",
	},
	"text_similarity": {
		signature: "text_similarity(left, right)",
		summary:   "Computes normalized Levenshtein similarity between two strings.",
		params: []builtinParamDoc{
			{name: "left", doc: "First string to compare."},
			{name: "right", doc: "Second string to compare."},
		},
	},
	"text_fuzzy_find": {
		signature: "text_fuzzy_find(query, candidates, maxDistance?)",
		summary:   "Finds the closest fuzzy match in an array of candidate strings.",
	},
	"text_jaro_winkler": {
		signature: "text_jaro_winkler(left, right)",
		summary:   "Computes Jaro-Winkler string similarity score.",
	},
	"regex_match": {signature: "regex_match(pattern, input)", summary: "Returns whether regex pattern matches input."},
	"regex_find":  {signature: "regex_find(pattern, input)", summary: "Finds the first regex match in input."},
	"regex_find_all": {
		signature: "regex_find_all(pattern, input, limit?)",
		summary:   "Finds all regex matches with optional result limit.",
	},
	"regex_replace": {
		signature: "regex_replace(pattern, input, replacement)",
		summary:   "Replaces all regex matches in input with replacement text.",
		params: []builtinParamDoc{
			{name: "pattern", doc: "Regular expression pattern."},
			{name: "input", doc: "Input string to transform."},
			{name: "replacement", doc: "Replacement text for each match."},
		},
	},
	"regex_capture_groups": {
		signature: "regex_capture_groups(pattern, input)",
		summary:   "Returns full regex capture array (full match plus groups).",
	},
	"policy_load": {
		signature: "policy_load(name, source)",
		summary:   "Loads a policy module by name from source text or config hash.",
	},
	"policy_eval": {
		signature: "policy_eval(policy, input)",
		summary:   "Evaluates a loaded policy and returns decision details.",
		params: []builtinParamDoc{
			{name: "policy", doc: "Policy name or handle."},
			{name: "input", doc: "Input data evaluated by the policy."},
		},
	},
	"policy_allow": {
		signature: "policy_allow(policy, input)",
		summary:   "Evaluates and returns allow/deny boolean for a policy.",
	},
	"policy_rules": {
		signature: "policy_rules(policy)",
		summary:   "Returns rule metadata exported by a loaded policy.",
	},
	"policy_trace": {
		signature: "policy_trace(policy, input)",
		summary:   "Runs policy evaluation with trace output for debugging rule flow.",
		params: []builtinParamDoc{
			{name: "policy", doc: "Policy name or handle."},
			{name: "input", doc: "Input data evaluated by the policy."},
		},
	},
	"cache_open": {
		signature: "cache_open(name)",
		summary:   "Opens or creates a named in-memory cache store.",
		params:    []builtinParamDoc{{name: "name", doc: "Cache namespace identifier."}},
	},
	"cache_put": {
		signature: "cache_put(name, key, value, ttlSeconds?)",
		summary:   "Stores a value in a named cache key with optional TTL.",
		params: []builtinParamDoc{
			{name: "name", doc: "Cache namespace identifier."},
			{name: "key", doc: "Cache key string."},
			{name: "value", doc: "Value to store."},
			{name: "ttlSeconds?", doc: "Optional expiration in seconds (0 for no expiry)."},
		},
	},
	"cache_get": {
		signature: "cache_get(name, key)",
		summary:   "Reads a value from cache and returns found/value fields.",
		params: []builtinParamDoc{
			{name: "name", doc: "Cache namespace identifier."},
			{name: "key", doc: "Cache key string."},
		},
	},
	"cache_delete": {
		signature: "cache_delete(name, key)",
		summary:   "Deletes a key from cache and returns whether it existed.",
	},
	"cache_keys": {
		signature: "cache_keys(name)",
		summary:   "Lists sorted cache keys for a cache namespace.",
	},
	"cache_stats": {
		signature: "cache_stats(name)",
		summary:   "Returns cache counters such as hits, misses, puts, deletes, and expires.",
		params:    []builtinParamDoc{{name: "name", doc: "Cache namespace identifier."}},
	},
	"cache_clear": {
		signature: "cache_clear(name)",
		summary:   "Clears all entries and resets relevant cache state.",
	},
	"process_list": {signature: "process_list()", summary: "Lists visible processes with pid, ppid, and executable name."},
	"process_tree": {
		signature: "process_tree(rootPid?)",
		summary:   "Returns descendant processes for a root pid (default current process).",
		params:    []builtinParamDoc{{name: "rootPid?", doc: "Optional root process ID; defaults to current process."}},
	},
	"process_open_files": {
		signature: "process_open_files(pid?)",
		summary:   "Lists open file paths for a process (platform dependent).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	"process_threads": {
		signature: "process_threads(pid?)",
		summary:   "Lists thread IDs for a process (platform dependent).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	"process_modules": {
		signature: "process_modules(pid?)",
		summary:   "Lists loaded module/library paths for a process.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	"process_hash": {
		signature: "process_hash(pid?)",
		summary:   "Computes SHA-256 hash metadata for a process executable.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	"process_memory_scan": {
		signature: "process_memory_scan(pid, pattern)",
		summary:   "Scans process memory for a string pattern (advisory/stub on some platforms).",
		params: []builtinParamDoc{
			{name: "pid", doc: "Target process ID to scan."},
			{name: "pattern", doc: "String pattern searched in process memory."},
		},
	},
	"process_env": {
		signature: "process_env(pid?)",
		summary:   "Returns environment variables for a process.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	"process_kill": {
		signature: "process_kill(pid, signal?)",
		summary:   "Sends a signal to a process (default SIGKILL semantics).",
		params: []builtinParamDoc{
			{name: "pid", doc: "Target process ID."},
			{name: "signal?", doc: "Optional integer signal number."},
		},
	},
	"exec_string": {
		signature: "exec_string(command, shell?)",
		summary:   "Executes a shell command string via security-guarded command execution.",
		params: []builtinParamDoc{
			{name: "command", doc: "Command text to execute."},
			{name: "shell?", doc: "Optional shell executable (defaults to powershell)."},
		},
	},
	"cmd_builder": {
		signature: "cmd_builder(shell?)",
		summary:   "Creates a command builder object for step-wise command composition.",
		params:    []builtinParamDoc{{name: "shell?", doc: "Optional shell executable (defaults to powershell)."}},
	},
	"cmd_add": {
		signature: "cmd_add(builder, arg)",
		summary:   "Appends an argument to a command builder.",
		params: []builtinParamDoc{
			{name: "builder", doc: "Builder hash returned by cmd_builder/cmd_add."},
			{name: "arg", doc: "Command line text appended as a new line."},
		},
	},
	"cmd_run": {
		signature: "cmd_run(builder)",
		summary:   "Executes a composed command and returns run output metadata.",
		params:    []builtinParamDoc{{name: "builder", doc: "Builder hash containing shell and command lines."}},
	},
	"fs_delete": {signature: "fs_delete(path)", summary: "Deletes a file from disk."},
	"fs_stat":   {signature: "fs_stat(path)", summary: "Returns file metadata such as size and timestamps."},
	"fs_list":   {signature: "fs_list(path)", summary: "Lists directory entries for a path."},
	"fs_mkdir":  {signature: "fs_mkdir(path)", summary: "Creates a directory path."},
	"fs_copy":   {signature: "fs_copy(src, dst)", summary: "Copies a file from source path to destination path."},
	"fs_move":   {signature: "fs_move(src, dst)", summary: "Moves or renames a file or directory."},
	"fs_hash":   {signature: "fs_hash(path)", summary: "Computes hash digests for a file."},
	"fs_walk":   {signature: "fs_walk(root)", summary: "Walks a directory tree and returns discovered paths."},
	"fs_metadata": {
		signature: "fs_metadata(path)",
		summary:   "Returns detailed filesystem metadata for a path.",
	},
	"fs_magic": {
		signature: "fs_magic(path)",
		summary:   "Infers file type/magic information from file contents.",
	},
	"fs_extract_strings": {
		signature: "fs_extract_strings(path, minLen?)",
		summary:   "Extracts printable strings from a file.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to source file."},
			{name: "minLen?", doc: "Optional minimum string length (default 4)."},
		},
	},
	"fs_diff": {
		signature: "fs_diff(leftPath, rightPath)",
		summary:   "Compares two files or directories and reports differences.",
	},
	"fs_carve": {
		signature: "fs_carve(path, type)",
		summary:   "Carves matching binary artifacts from a file by known artifact type.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to source file."},
			{name: "type", doc: "Artifact type signature such as pe/elf/pdf/zip."},
		},
	},
	"fs_entropy": {
		signature: "fs_entropy(path)",
		summary:   "Computes file entropy for packed/encrypted artifact detection.",
	},
	"bin_pe_parse": {
		signature: "bin_pe_parse(path)",
		summary:   "Parses PE headers and returns core binary metadata.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to PE file."}},
	},
	"bin_elf_parse": {
		signature: "bin_elf_parse(path)",
		summary:   "Parses ELF headers and returns core binary metadata.",
	},
	"bin_dwarf_parse": {
		signature: "bin_dwarf_parse(path)",
		summary:   "Parses DWARF metadata and reports compile unit information.",
	},
	"bin_strings": {
		signature: "bin_strings(path, minLen?)",
		summary:   "Extracts printable strings from a binary.",
	},
	"bin_entropy": {
		signature: "bin_entropy(path)",
		summary:   "Computes binary entropy signal.",
	},
	"bin_yara_scan": {
		signature: "bin_yara_scan(path, rules)",
		summary:   "Runs YARA-like signature scanning on a binary.",
	},
	"bin_imports": {
		signature: "bin_imports(path)",
		summary:   "Returns imported symbols/libraries from a binary.",
	},
	"bin_sections": {
		signature: "bin_sections(path)",
		summary:   "Returns binary section table information.",
	},
	"net_syn_scan": {signature: "net_syn_scan(target, ports)", summary: "Performs TCP SYN scanning for target ports."},
	"net_udp_scan": {signature: "net_udp_scan(target, ports)", summary: "Performs UDP scanning for target ports."},
	"net_banner":   {signature: "net_banner(address)", summary: "Collects service banner text from a network endpoint."},
	"net_tls_fingerprint": {
		signature: "net_tls_fingerprint(address, timeoutMs)",
		summary:   "Collects TLS certificate and handshake fingerprint metadata.",
		params: []builtinParamDoc{
			{name: "address", doc: "Host:port endpoint for TLS connection."},
			{name: "timeoutMs", doc: "Dial timeout in milliseconds."},
		},
	},
	"net_dns_query": {
		signature: "net_dns_query(name, qtype)",
		summary:   "Queries DNS records for a hostname.",
		params: []builtinParamDoc{
			{name: "name", doc: "DNS name or reverse-lookup value."},
			{name: "qtype", doc: "Query type: A, AAAA, IP, CNAME, MX, TXT, NS, or PTR."},
		},
	},
	"net_pcap_analyze": {
		signature: "net_pcap_analyze(path)",
		summary:   "Analyzes PCAP captures and returns flow/session signals.",
	},
	"net_capture_raw": {
		signature: "net_capture_raw()",
		summary:   "Captures raw packets from an interface for a time window.",
	},
	"net_flow_reconstruct": {
		signature: "net_flow_reconstruct(packets)",
		summary:   "Reconstructs higher-level flows from packet records.",
		params:    []builtinParamDoc{{name: "packets", doc: "Array of packet hashes with src/dst/ports/protocol/bytes fields."}},
	},
	"net_os_fingerprint": {
		signature: "net_os_fingerprint(target, timeoutMs)",
		summary:   "Infers probable remote OS fingerprint from network responses.",
		params: []builtinParamDoc{
			{name: "target", doc: "Target host or address."},
			{name: "timeoutMs", doc: "Probe timeout in milliseconds."},
		},
	},
	"reg_open": {
		signature: "reg_open(path)",
		summary:   "Opens a registry hive data source and returns a handle.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to hive JSON file."}},
	},
	"reg_enum_keys": {
		signature: "reg_enum_keys(hiveHandle, keyPath)",
		summary:   "Enumerates subkeys under a registry path.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path to enumerate."},
		},
	},
	"reg_enum_values": {
		signature: "reg_enum_values(hiveHandle, keyPath)",
		summary:   "Enumerates values under a registry path.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path to enumerate."},
		},
	},
	"reg_get_value": {
		signature: "reg_get_value(hiveHandle, keyPath, valueName)",
		summary:   "Reads a specific registry value with type metadata.",
		params: []builtinParamDoc{
			{name: "hiveHandle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Registry path that contains the value."},
			{name: "valueName", doc: "Registry value name to fetch."},
		},
	},
	"reg_deleted_keys": {
		signature: "reg_deleted_keys(hiveHandle)",
		summary:   "Lists deleted keys recovered from hive artifacts.",
	},
	"reg_timeline": {
		signature: "reg_timeline(hiveHandle)",
		summary:   "Returns timeline events extracted from an opened registry hive.",
		params:    []builtinParamDoc{{name: "hiveHandle", doc: "Handle returned by reg_open."}},
	},
	"email_parse": {
		signature: "email_parse(raw)",
		summary:   "Parses a raw email message into headers, body parts, and attachments.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	"email_headers": {
		signature: "email_headers(raw)",
		summary:   "Parses and returns message headers from raw email input.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	"email_attachments": {
		signature: "email_attachments(raw)",
		summary:   "Extracts attachment metadata/content details from raw email input.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	"email_spf_dkim": {
		signature: "email_spf_dkim(raw)",
		summary:   "Evaluates SPF/DKIM/DMARC signals from message headers.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	"email_urls": {
		signature: "email_urls(raw)",
		summary:   "Extracts and normalizes URLs from email headers and body.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	"mem_map": {
		signature: "mem_map(path)",
		summary:   "Builds memory map segments from a memory dump file.",
	},
	"mem_read": {
		signature: "mem_read(path, offset, size)",
		summary:   "Reads a byte range from a memory image.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "offset", doc: "Starting offset in bytes."},
			{name: "size", doc: "Number of bytes to read."},
		},
	},
	"mem_scan": {
		signature: "mem_scan(path, pattern)",
		summary:   "Scans a memory image for a string/byte pattern.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "pattern", doc: "String pattern to search for."},
		},
	},
	"mem_strings": {
		signature: "mem_strings(path, minLen?)",
		summary:   "Extracts printable strings from memory image data.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to memory image or dump file."},
			{name: "minLen?", doc: "Optional minimum string length (default 4)."},
		},
	},
	"mem_find_pe": {
		signature: "mem_find_pe(path)",
		summary:   "Finds PE header offsets in memory image data.",
	},
	"mem_find_shellcode": {
		signature: "mem_find_shellcode(path)",
		summary:   "Scans a memory dump file for common shellcode byte signatures.",
		params:    []builtinParamDoc{{name: "path", doc: "Path to memory image or dump file."}},
	},
	"detect_persistence": {
		signature: "detect_persistence(facts)",
		summary:   "Detects persistence indicators from host evidence facts.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash containing autorun/startup/task evidence."}},
	},
	"detect_injection": {
		signature: "detect_injection(facts)",
		summary:   "Detects probable code injection signals from memory-derived evidence.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash containing evidence such as mem_path."}},
	},
	"detect_network_beacon": {
		signature: "detect_network_beacon(flows)",
		summary:   "Detects beacon-like repeated outbound network destinations.",
		params:    []builtinParamDoc{{name: "flows", doc: "Array of flow hashes that include destination endpoint data."}},
	},
	"detect_priv_esc": {
		signature: "detect_priv_esc(facts)",
		summary:   "Detects potential privilege-escalation indicators from host facts.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash of privilege-related evidence and boolean checks."}},
	},
	"detect_suspicious_files": {
		signature: "detect_suspicious_files(paths)",
		summary:   "Detects suspicious file artifacts using extension/path heuristics.",
		params:    []builtinParamDoc{{name: "paths", doc: "Array of filesystem paths to inspect."}},
	},
	"net_resolve":          {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses."},
	"net_dial":             {signature: "net_dial(address)", summary: "Opens a network connection."},
	"db_open":              {signature: "db_open()", summary: "Creates an in-memory graph database handle."},
	"db_open_disk":         {signature: "db_open_disk(path)", summary: "Opens or creates a disk-backed graph database.", params: []builtinParamDoc{{name: "path", doc: "Database file path."}}},
	"db_close":             {signature: "db_close(db)", summary: "Closes a graph database handle and flushes pending state.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	"db_add_node":          {signature: "db_add_node(db, label, props)", summary: "Adds a node to the graph database.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "label", doc: "Node label/category."}, {name: "props", doc: "Node properties hash."}}},
	"db_add_edge":          {signature: "db_add_edge(db, from, to, label, props)", summary: "Adds an edge between graph nodes.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}, {name: "label", doc: "Edge label/type."}, {name: "props", doc: "Edge properties hash."}}},
	"db_add_artifact":      {signature: "db_add_artifact(db, artifact)", summary: "Adds a forensic artifact entity to the graph.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "artifact", doc: "Artifact hash payload."}}},
	"db_add_relation":      {signature: "db_add_relation(db, from, to, relation, props?)", summary: "Adds a named relation edge between entities.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source entity ID."}, {name: "to", doc: "Destination entity ID."}, {name: "relation", doc: "Relation type string."}, {name: "props?", doc: "Optional relation properties hash."}}},
	"db_index_prop":        {signature: "db_index_prop(db, key)", summary: "Builds or updates an index on a property key.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "key", doc: "Property key to index."}}},
	"db_query_nodes":       {signature: "db_query_nodes(db, filter)", summary: "Queries nodes by label/properties filter.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "filter", doc: "Filter hash or query object."}}},
	"db_query":             {signature: "db_query(db, query)", summary: "Executes a graph query expression and returns results.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "query", doc: "Query expression string."}}},
	"db_bfs":               {signature: "db_bfs(db, start, maxDepth?)", summary: "Performs breadth-first graph traversal from a start node.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "start", doc: "Start node ID."}, {name: "maxDepth?", doc: "Optional traversal depth limit."}}},
	"db_shortest_path":     {signature: "db_shortest_path(db, from, to)", summary: "Computes shortest path between two graph nodes.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}}},
	"db_timeline":          {signature: "db_timeline(db, opts?)", summary: "Builds chronological timeline views from graph evidence.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "opts?", doc: "Optional timeline filtering options."}}},
	"db_stats":             {signature: "db_stats(db)", summary: "Returns graph database statistics.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	"bytes_len":            {signature: "bytes_len(data)", summary: "Returns length of a bytes value."},
	"bytes_get":            {signature: "bytes_get(data, index)", summary: "Reads one byte at index as integer."},
	"bytes_slice":          {signature: "bytes_slice(data, start, end)", summary: "Returns byte sub-slice from start to end."},
	"bytes_hex":            {signature: "bytes_hex(data)", summary: "Returns uppercase hexadecimal representation of bytes."},
	"bytes_cstr_at":        {signature: "bytes_cstr_at(data, offset)", summary: "Reads null-terminated string from bytes at offset."},
	"bytes_char_from_int":  {signature: "bytes_char_from_int(value)", summary: "Converts an integer byte value to a single-character string."},
	"bytes_int_from_char":  {signature: "bytes_int_from_char(char)", summary: "Converts a single-character string to its integer byte value."},
	"bytes_read_u16_le":    {signature: "bytes_read_u16_le(data, offset)", summary: "Reads unsigned 16-bit little-endian integer from bytes at offset."},
	"bytes_read_u16_be":    {signature: "bytes_read_u16_be(data, offset)", summary: "Reads unsigned 16-bit big-endian integer from bytes at offset."},
	"bytes_read_u32_le":    {signature: "bytes_read_u32_le(data, offset)", summary: "Reads unsigned 32-bit little-endian integer from bytes at offset."},
	"bytes_read_u32_be":    {signature: "bytes_read_u32_be(data, offset)", summary: "Reads unsigned 32-bit big-endian integer from bytes at offset."},
	"bytes_read_u64_le":    {signature: "bytes_read_u64_le(data, offset)", summary: "Reads unsigned 64-bit little-endian integer from bytes at offset."},
	"bytes_read_u64_be":    {signature: "bytes_read_u64_be(data, offset)", summary: "Reads unsigned 64-bit big-endian integer from bytes at offset."},
	"bytes_write_u16_le":   {signature: "bytes_write_u16_le(data, offset, value)", summary: "Writes unsigned 16-bit little-endian integer into bytes at offset."},
	"bytes_write_u16_be":   {signature: "bytes_write_u16_be(data, offset, value)", summary: "Writes unsigned 16-bit big-endian integer into bytes at offset."},
	"bytes_write_u32_le":   {signature: "bytes_write_u32_le(data, offset, value)", summary: "Writes unsigned 32-bit little-endian integer into bytes at offset."},
	"bytes_write_u32_be":   {signature: "bytes_write_u32_be(data, offset, value)", summary: "Writes unsigned 32-bit big-endian integer into bytes at offset."},
	"bytes_write_u64_le":   {signature: "bytes_write_u64_le(data, offset, value)", summary: "Writes unsigned 64-bit little-endian integer into bytes at offset."},
	"bytes_write_u64_be":   {signature: "bytes_write_u64_be(data, offset, value)", summary: "Writes unsigned 64-bit big-endian integer into bytes at offset."},
	"bytes_cursor_new":     {signature: "bytes_cursor_new(data)", summary: "Creates a cursor for structured byte parsing."},
	"bytes_cursor_tell":    {signature: "bytes_cursor_tell(cursor)", summary: "Returns current cursor position."},
	"bytes_cursor_seek":    {signature: "bytes_cursor_seek(cursor, offset)", summary: "Moves cursor to an absolute offset."},
	"bytes_cursor_eof":     {signature: "bytes_cursor_eof(cursor)", summary: "Returns whether cursor is at end-of-buffer."},
	"bytes_cursor_read_u8": {signature: "bytes_cursor_read_u8(cursor)", summary: "Reads one unsigned byte from cursor."},
	"bytes_cursor_read_u16_le": {
		signature: "bytes_cursor_read_u16_le(cursor)",
		summary:   "Reads unsigned 16-bit little-endian integer from cursor.",
	},
	"bytes_cursor_read_u16_be": {
		signature: "bytes_cursor_read_u16_be(cursor)",
		summary:   "Reads unsigned 16-bit big-endian integer from cursor.",
	},
	"bytes_cursor_read_u32_le": {
		signature: "bytes_cursor_read_u32_le(cursor)",
		summary:   "Reads unsigned 32-bit little-endian integer from cursor.",
	},
	"bytes_cursor_read_u32_be": {
		signature: "bytes_cursor_read_u32_be(cursor)",
		summary:   "Reads unsigned 32-bit big-endian integer from cursor.",
	},
	"bytes_cursor_read_u64_le": {
		signature: "bytes_cursor_read_u64_le(cursor)",
		summary:   "Reads unsigned 64-bit little-endian integer from cursor.",
	},
	"bytes_cursor_read_u64_be": {
		signature: "bytes_cursor_read_u64_be(cursor)",
		summary:   "Reads unsigned 64-bit big-endian integer from cursor.",
	},
	"security_diagnostics": {signature: "security_diagnostics()", summary: "Returns security diagnostics for the current runtime."},
	"sandbox_status":       {signature: "sandbox_status()", summary: "Returns sandbox-detection status information."},
	"debug_status":         {signature: "debug_status()", summary: "Returns runtime/debugger status information."},
}

var builtinFamilyDocs = []builtinFamilyDoc{
	{prefix: "bytes_", summary: "Bytes utility for reading/writing binary data."},
	{prefix: "db_", summary: "Graph database helper for nodes, edges, indexing, or traversal."},
	{prefix: "fs_", summary: "Filesystem helper for reading/writing/managing files and directories."},
	{prefix: "http_", summary: "HTTP helper for network requests."},
	{prefix: "net_", summary: "Network helper for address resolution, sockets, scanning, and capture analysis."},
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
}

var keywordHoverDocs = map[string]string{
	"fn":       "Defines an anonymous function literal. Functions can capture outer variables and be assigned to names.",
	"let":      "Declares a new binding. Use let name = value; to store values for later use.",
	"if":       "Conditional expression. Executes the consequence block when the condition is truthy, otherwise runs else if present.",
	"else":     "Alternative branch for an if expression.",
	"return":   "Returns one or more values from the current function.",
	"for":      "Loop construct with init, condition, and post expressions: for (init; cond; post) { ... }.",
	"break":    "Exits the nearest enclosing loop immediately.",
	"continue": "Skips to the next iteration of the nearest enclosing loop.",
	"struct":   "Declares a struct type with named fields.",
	"enum":     "Declares a closed set of named variants.",
	"macro":    "Declares a macro literal for AST-level metaprogramming.",
	"true":     "Boolean literal representing truth.",
	"false":    "Boolean literal representing falsehood.",
}

func builtinHoverText(name string) (string, bool) {
	if doc, ok := builtinDocs[name]; ok {
		if len(doc.params) == 0 {
			return fmt.Sprintf("builtin `%s`\n\n%s", doc.signature, doc.summary), true
		}

		parts := make([]string, 0, len(doc.params))
		for _, p := range doc.params {
			parts = append(parts, fmt.Sprintf("- `%s`: %s", p.name, p.doc))
		}
		return fmt.Sprintf("builtin `%s`\n\n%s\n\n%s", doc.signature, doc.summary, strings.Join(parts, "\n")), true
	}

	if summary, ok := builtinFamilySummary(name); ok {
		return fmt.Sprintf("builtin `%s(...)`\n\n%s", name, summary), true
	}
	if builtin.GetBuiltinByName(name) != nil {
		return fmt.Sprintf("builtin `%s(...)`\n\nBuiltin function.", name), true
	}

	return "", false
}

func builtinFamilySummary(name string) (string, bool) {
	for _, family := range builtinFamilyDocs {
		if strings.HasPrefix(name, family.prefix) {
			return family.summary, true
		}
	}
	return "", false
}

func keywordHoverText(keyword string) (string, bool) {
	doc, ok := keywordHoverDocs[keyword]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("keyword `%s`\n\n%s", keyword, doc), true
}

func languageSnippetCompletionItems() []lsp.CompletionItem {
	snippetKind := lsp.CompletionItemKindSnippet
	snippetFormat := lsp.InsertTextFormatSnippet

	return []lsp.CompletionItem{
		{
			Label:            "if / else",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("if (${1:condition}) {\n  ${2:// todo}\n} else {\n  ${3:// todo}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Conditional block with an else branch.",
			},
		},
		{
			Label:            "if guard return",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("if (!(${1:condition})) {\n  return ${2:nil};\n}\n${3:// continue}"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Guard clause with early return."},
		},
		{
			Label:            "for loop",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:let i = 0}; ${2:i < n}; ${3:i = i + 1}) {\n  ${4:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Classic for-loop template.",
			},
		},
		{
			Label:            "for loop over array",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("for (${1:let i = 0}; i < len(${2:items}); i = i + 1) {\n  let ${3:item} = ${2:items}[i];\n  ${4:// body}\n}"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Loop over all array elements by index."},
		},
		{
			Label:            "function declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:name} = fn(${2:param}) {\n  ${3:// body}\n};"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "User-defined function binding.",
			},
		},
		{
			Label:            "function declaration with docs",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("// ${1:Describe what this function does}\nlet ${2:name} = fn(${3:param}) {\n  ${4:// body}\n};"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Function template with leading doc comment."},
		},
		{
			Label:            "struct declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("struct ${1:Name} { ${2:field1}; ${3:field2}; }"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Struct type declaration.",
			},
		},
		{
			Label:            "struct value",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:instance} = ${2:Type} { ${3:field}: ${4:value} };"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Construct a struct value."},
		},
		{
			Label:            "enum declaration",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("enum ${1:Name} { ${2:VariantA}, ${3:VariantB} }"),
			InsertTextFormat: &snippetFormat,
			Documentation: lsp.MarkupContent{
				Kind:  lsp.MarkupKindMarkdown,
				Value: "Enum declaration with named variants.",
			},
		},
		{
			Label:            "enum variant usage",
			Kind:             &snippetKind,
			Detail:           strPtr("Snippet"),
			InsertText:       strPtr("let ${1:value} = ${2:Enum}.${3:Variant};"),
			InsertTextFormat: &snippetFormat,
			Documentation:    lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: "Reference an enum variant."},
		},
	}
}

func builtinSignatureInformation(name string) (lsp.SignatureInformation, bool) {
	if doc, ok := builtinDocs[name]; ok {
		sig := lsp.SignatureInformation{Label: doc.signature}
		sig.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: doc.summary}
		if len(doc.params) == 0 {
			return sig, true
		}

		params := make([]lsp.ParameterInformation, 0, len(doc.params))
		for _, p := range doc.params {
			param := lsp.ParameterInformation{Label: p.name}
			if p.doc != "" {
				param.Documentation = lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: p.doc}
			}
			params = append(params, param)
		}
		sig.Parameters = params
		return sig, true
	}

	if hover, ok := builtinHoverText(name); ok {
		return lsp.SignatureInformation{
			Label:         fmt.Sprintf("%s(...)", name),
			Documentation: lsp.MarkupContent{Kind: lsp.MarkupKindMarkdown, Value: hover},
		}, true
	}

	return lsp.SignatureInformation{}, false
}

func strPtr(s string) *string { return &s }
