# Mutant Language Reference

This document is the practical reference for Mutant language features, reserved keywords, and builtins.

Source of truth:
- Keywords: token/token.go
- Builtins registry: builtin/builtin.go
- Builtin names/constants: builtin/names.go
- Builtin teaching metadata/signatures: builtin/metadata.go

## Language Features

Mutant supports:
- Variables and assignment with let
- Primitive literals: integers, floats, booleans, strings
- Compound literals: arrays, hashes, struct literals
- Prefix operators: ! and unary -
- Infix operators: + - * / % < > == !=
- Indexing and field access
- Conditionals: if / else
- Loops: for, with break and continue
- Functions and function calls
- Return statements
- Macros
- Type declarations: struct and enum

Notes:
- String literals are simple quoted strings; escape-sequence behavior is intentionally limited.
- Semicolons are used as statement separators in common style.

## Reserved Keywords

- break
- continue
- else
- enum
- false
- fn
- for
- if
- let
- macro
- return
- struct
- true

## Builtins

Total builtins currently registered: 211

### Core

- `first(array)` - Returns the first element of an array.
- `gets()` - Reads a line of input from stdin.
- `last(array)` - Returns the last element of an array.
- `len(value)` - Returns the length of a string, array, hash, or bytes value.
- `pop(array)` - Returns a new array without the last element.
- `push(array, value)` - Returns a new array with value appended.
- `putf(format, ...values)` - Formats and prints values using a format string.
- `putln(value)` - Prints a value followed by a newline.
- `rest(array)` - Returns a new array without the first element.

### Text

- `text_contains(haystack, needle)` - Returns whether a string contains a substring.
- `text_count(haystack, needle)` - Counts non-overlapping substring occurrences.
- `text_fuzzy_find(query, candidates, maxDistance?)` - Finds the closest fuzzy match in an array of candidate strings.
- `text_index(haystack, needle)` - Returns the first index of substring occurrence, or -1.
- `text_jaro_winkler(left, right)` - Computes Jaro-Winkler string similarity score.
- `text_levenshtein(left, right)` - Computes Levenshtein edit distance between two strings.
- `text_replace(text, old, new)` - Replaces substring occurrences in text.
- `text_similarity(left, right)` - Computes normalized Levenshtein similarity between two strings.
- `text_split(text, sep)` - Splits text by separator and returns an array of parts.

### Regex

- `regex_capture_groups(pattern, input)` - Returns full regex capture array (full match plus groups).
- `regex_find(pattern, input)` - Finds the first regex match in input.
- `regex_find_all(pattern, input, limit?)` - Finds all regex matches with optional result limit.
- `regex_match(pattern, input)` - Returns whether regex pattern matches input.
- `regex_replace(pattern, input, replacement)` - Replaces all regex matches in input with replacement text.

### Policy

- `policy_allow(policy, input)` - Evaluates and returns allow/deny boolean for a policy.
- `policy_eval(policy, input)` - Evaluates a loaded policy and returns decision details.
- `policy_load(name, source)` - Loads a policy module by name from source text or config hash.
- `policy_rules(policy)` - Returns rule metadata exported by a loaded policy.
- `policy_trace(policy, input)` - Runs policy evaluation with trace output for debugging rule flow.

### Cache

- `cache_clear(name)` - Clears all entries and resets relevant cache state.
- `cache_close(...)` - In-memory cache helper for open/get/put/delete/stats workflows.
- `cache_delete(name, key)` - Deletes a key from cache and returns whether it existed.
- `cache_get(name, key)` - Reads a value from cache and returns found/value fields.
- `cache_keys(name)` - Lists sorted cache keys for a cache namespace.
- `cache_open(name)` - Opens or creates a named in-memory cache store.
- `cache_put(name, key, value, ttlSeconds?)` - Stores a value in a named cache key with optional TTL.
- `cache_stats(name)` - Returns cache counters such as hits, misses, puts, deletes, and expires.

### System and Process

- `cmd_add(builder, arg)` - Appends an argument to a command builder.
- `cmd_builder(shell?)` - Creates a command builder object for step-wise command composition.
- `cmd_run(builder)` - Executes a composed command and returns run output metadata.
- `debug_status()` - Returns runtime/debugger status information.
- `exec_string(command, shell?)` - Executes a shell command string via security-guarded command execution.
- `process_env(pid?)` - Returns environment variables for a process.
- `process_hash(pid?)` - Computes SHA-256 hash metadata for a process executable.
- `process_kill(pid, signal?)` - Sends a signal to a process (default SIGKILL semantics).
- `process_list()` - Lists visible processes with pid, ppid, and executable name.
- `process_memory_scan(pid, pattern)` - Scans process memory for a string pattern (advisory/stub on some platforms).
- `process_modules(pid?)` - Lists loaded module/library paths for a process.
- `process_open_files(pid?)` - Lists open file paths for a process (platform dependent).
- `process_threads(pid?)` - Lists thread IDs for a process (platform dependent).
- `process_tree(rootPid?)` - Returns descendant processes for a root pid (default current process).
- `sandbox_status()` - Returns sandbox-detection status information.
- `security_diagnostics()` - Returns security diagnostics for the current runtime.

### Filesystem

- `fs_append(path, data)` - Appends data to the end of a file.
- `fs_carve(path, type)` - Carves matching binary artifacts from a file by known artifact type.
- `fs_copy(src, dst)` - Copies a file from source path to destination path.
- `fs_delete(path)` - Deletes a file from disk.
- `fs_diff(leftPath, rightPath)` - Compares two files or directories and reports differences.
- `fs_entropy(path)` - Computes file entropy for packed/encrypted artifact detection.
- `fs_exists(path)` - Returns whether a file or directory exists.
- `fs_extract_strings(path, minLen?)` - Extracts printable strings from a file.
- `fs_hash(path)` - Computes hash digests for a file.
- `fs_list(path)` - Lists directory entries for a path.
- `fs_magic(path)` - Infers file type/magic information from file contents.
- `fs_metadata(path)` - Returns detailed filesystem metadata for a path.
- `fs_mkdir(path)` - Creates a directory path.
- `fs_move(src, dst)` - Moves or renames a file or directory.
- `fs_read(path)` - Reads file contents from disk.
- `fs_stat(path)` - Returns file metadata such as size and timestamps.
- `fs_walk(root)` - Walks a directory tree and returns discovered paths.
- `fs_write(path, data)` - Writes data to a file, replacing existing contents.

### Filesystem Parsers

- `ewf_close(...)` - EWF image parser helper for metadata lookup and offset reads.
- `ewf_metadata(...)` - EWF image parser helper for metadata lookup and offset reads.
- `ewf_open(...)` - EWF image parser helper for metadata lookup and offset reads.
- `ewf_read_at(...)` - EWF image parser helper for metadata lookup and offset reads.
- `ext_close(...)` - ext filesystem parser helper for file listing, metadata, and data extraction.
- `ext_list_files(...)` - ext filesystem parser helper for file listing, metadata, and data extraction.
- `ext_metadata(...)` - ext filesystem parser helper for file listing, metadata, and data extraction.
- `ext_open(...)` - ext filesystem parser helper for file listing, metadata, and data extraction.
- `ext_read_file(...)` - ext filesystem parser helper for file listing, metadata, and data extraction.
- `fat_close(...)` - FAT filesystem parser helper for file listing, metadata, and data extraction.
- `fat_list_files(...)` - FAT filesystem parser helper for file listing, metadata, and data extraction.
- `fat_metadata(...)` - FAT filesystem parser helper for file listing, metadata, and data extraction.
- `fat_open(...)` - FAT filesystem parser helper for file listing, metadata, and data extraction.
- `fat_read_file(...)` - FAT filesystem parser helper for file listing, metadata, and data extraction.
- `hfs_close(...)` - HFS filesystem parser helper for file listing, metadata, and data extraction.
- `hfs_list_files(...)` - HFS filesystem parser helper for file listing, metadata, and data extraction.
- `hfs_metadata(...)` - HFS filesystem parser helper for file listing, metadata, and data extraction.
- `hfs_open(...)` - HFS filesystem parser helper for file listing, metadata, and data extraction.
- `hfs_read_file(...)` - HFS filesystem parser helper for file listing, metadata, and data extraction.
- `ntfs_close(...)` - NTFS filesystem parser helper for file listing, metadata, and data extraction.
- `ntfs_list_files(...)` - NTFS filesystem parser helper for file listing, metadata, and data extraction.
- `ntfs_metadata(...)` - NTFS filesystem parser helper for file listing, metadata, and data extraction.
- `ntfs_open(...)` - NTFS filesystem parser helper for file listing, metadata, and data extraction.
- `ntfs_read_file(...)` - NTFS filesystem parser helper for file listing, metadata, and data extraction.
- `raw_close(...)` - Raw disk image helper for metadata lookup and offset reads.
- `raw_metadata(...)` - Raw disk image helper for metadata lookup and offset reads.
- `raw_open(...)` - Raw disk image helper for metadata lookup and offset reads.
- `raw_read_at(...)` - Raw disk image helper for metadata lookup and offset reads.
- `table_close(...)` - Partition table parser helper for table and partition metadata.
- `table_list_partitions(...)` - Partition table parser helper for table and partition metadata.
- `table_open(...)` - Partition table parser helper for table and partition metadata.
- `table_partition_info(...)` - Partition table parser helper for table and partition metadata.
- `vhdi_close(...)` - VHD image parser helper for metadata lookup and offset reads.
- `vhdi_map_offset(...)` - VHD image parser helper for metadata lookup and offset reads.
- `vhdi_metadata(...)` - VHD image parser helper for metadata lookup and offset reads.
- `vhdi_open(...)` - VHD image parser helper for metadata lookup and offset reads.
- `vhdi_read_at(...)` - VHD image parser helper for metadata lookup and offset reads.
- `xfat_close(...)` - exFAT filesystem parser helper for file listing, metadata, and data extraction.
- `xfat_list_files(...)` - exFAT filesystem parser helper for file listing, metadata, and data extraction.
- `xfat_metadata(...)` - exFAT filesystem parser helper for file listing, metadata, and data extraction.
- `xfat_open(...)` - exFAT filesystem parser helper for file listing, metadata, and data extraction.
- `xfat_read_file(...)` - exFAT filesystem parser helper for file listing, metadata, and data extraction.
- `xfs_close(...)` - XFS filesystem parser helper for file listing, metadata, and data extraction.
- `xfs_list_files(...)` - XFS filesystem parser helper for file listing, metadata, and data extraction.
- `xfs_metadata(...)` - XFS filesystem parser helper for file listing, metadata, and data extraction.
- `xfs_open(...)` - XFS filesystem parser helper for file listing, metadata, and data extraction.
- `xfs_read_file(...)` - XFS filesystem parser helper for file listing, metadata, and data extraction.

### Binary Analysis

- `bin_dwarf_parse(path)` - Parses DWARF metadata and reports compile unit information.
- `bin_elf_parse(path)` - Parses ELF headers and returns core binary metadata.
- `bin_entropy(path)` - Computes binary entropy signal.
- `bin_imports(path)` - Returns imported symbols/libraries from a binary.
- `bin_pe_parse(path)` - Parses PE headers and returns core binary metadata.
- `bin_sections(path)` - Returns binary section table information.
- `bin_strings(path, minLen?)` - Extracts printable strings from a binary.
- `bin_yara_scan(path, rules)` - Runs YARA-like signature scanning on a binary.

### Network

- `net_banner(address)` - Collects service banner text from a network endpoint.
- `net_capture_raw()` - Captures raw packets from an interface for a time window.
- `net_dial(address)` - Opens a network connection.
- `net_dns_query(name, qtype)` - Queries DNS records for a hostname.
- `net_flow_reconstruct(packets)` - Reconstructs higher-level flows from packet records.
- `net_os_fingerprint(target, timeoutMs)` - Infers probable remote OS fingerprint from network responses.
- `net_pcap_analyze(path)` - Analyzes PCAP captures and returns flow/session signals.
- `net_resolve(host)` - Resolves a host name to network addresses.
- `net_syn_scan(target, ports)` - Performs TCP SYN scanning for target ports.
- `net_tls_fingerprint(address, timeoutMs)` - Collects TLS certificate and handshake fingerprint metadata.
- `net_udp_scan(target, ports)` - Performs UDP scanning for target ports.

### Registry

- `reg_close(...)` - Registry forensics helper for hives, keys, values, and timeline analysis.
- `reg_deleted_keys(hiveHandle)` - Lists deleted keys recovered from hive artifacts.
- `reg_enum_keys(hiveHandle, keyPath)` - Enumerates subkeys under a registry path.
- `reg_enum_values(hiveHandle, keyPath)` - Enumerates values under a registry path.
- `reg_get_value(hiveHandle, keyPath, valueName)` - Reads a specific registry value with type metadata.
- `reg_open(path)` - Opens a registry hive data source and returns a handle.
- `reg_timeline(hiveHandle)` - Returns timeline events extracted from an opened registry hive.

### Email

- `email_attachments(raw)` - Extracts attachment metadata/content details from raw email input.
- `email_headers(raw)` - Parses and returns message headers from raw email input.
- `email_parse(raw)` - Parses a raw email message into headers, body parts, and attachments.
- `email_spf_dkim(raw)` - Evaluates SPF/DKIM/DMARC signals from message headers.
- `email_urls(raw)` - Extracts and normalizes URLs from email headers and body.

### Memory

- `mem_find_pe(path)` - Finds PE header offsets in memory image data.
- `mem_find_shellcode(path)` - Scans a memory dump file for common shellcode byte signatures.
- `mem_map(path)` - Builds memory map segments from a memory dump file.
- `mem_read(path, offset, size)` - Reads a byte range from a memory image.
- `mem_scan(path, pattern)` - Scans a memory image for a string/byte pattern.
- `mem_strings(path, minLen?)` - Extracts printable strings from memory image data.

### Detection

- `detect_injection(facts)` - Detects probable code injection signals from memory-derived evidence.
- `detect_network_beacon(flows)` - Detects beacon-like repeated outbound network destinations.
- `detect_persistence(facts)` - Detects persistence indicators from host evidence facts.
- `detect_priv_esc(facts)` - Detects potential privilege-escalation indicators from host facts.
- `detect_suspicious_files(paths)` - Detects suspicious file artifacts using extension/path heuristics.

### HTTP

- `http_get(url)` - Performs an HTTP GET request.
- `http_post(url, body)` - Performs an HTTP POST request.
- `http_request(method, url, opts)` - Performs a configurable HTTP request.

### JSON

- `json_parse(text)` - Parses JSON text into Mutant values.
- `json_stringify(value)` - Serializes Mutant values into JSON text.

### Lua

- `lua_run_file(path)` - Runs a Lua script from a file.
- `lua_run_http(url)` - Fetches and runs a Lua script from an HTTP endpoint.
- `lua_run_string(code)` - Runs a Lua script from a string.

### Graph Database

- `db_add_artifact(db, artifact)` - Adds a forensic artifact entity to the graph.
- `db_add_edge(db, from, to, label, props)` - Adds an edge between graph nodes.
- `db_add_node(db, label, props)` - Adds a node to the graph database.
- `db_add_relation(db, from, to, relation, props?)` - Adds a named relation edge between entities.
- `db_bfs(db, start, maxDepth?)` - Performs breadth-first graph traversal from a start node.
- `db_close(db)` - Closes a graph database handle and flushes pending state.
- `db_index_prop(db, key)` - Builds or updates an index on a property key.
- `db_open()` - Creates an in-memory graph database handle.
- `db_open_disk(path)` - Opens or creates a disk-backed graph database.
- `db_query(db, query)` - Executes a graph query expression and returns results.
- `db_query_nodes(db, filter)` - Queries nodes by label/properties filter.
- `db_shortest_path(db, from, to)` - Computes shortest path between two graph nodes.
- `db_stats(db)` - Returns graph database statistics.
- `db_timeline(db, opts?)` - Builds chronological timeline views from graph evidence.

### Bytes

- `bytes_char_from_int(value)` - Converts an integer byte value to a single-character string.
- `bytes_cstr_at(data, offset)` - Reads null-terminated string from bytes at offset.
- `bytes_cursor_eof(cursor)` - Returns whether cursor is at end-of-buffer.
- `bytes_cursor_new(data)` - Creates a cursor for structured byte parsing.
- `bytes_cursor_read_u16_be(cursor)` - Reads unsigned 16-bit big-endian integer from cursor.
- `bytes_cursor_read_u16_le(cursor)` - Reads unsigned 16-bit little-endian integer from cursor.
- `bytes_cursor_read_u32_be(cursor)` - Reads unsigned 32-bit big-endian integer from cursor.
- `bytes_cursor_read_u32_le(cursor)` - Reads unsigned 32-bit little-endian integer from cursor.
- `bytes_cursor_read_u64_be(cursor)` - Reads unsigned 64-bit big-endian integer from cursor.
- `bytes_cursor_read_u64_le(cursor)` - Reads unsigned 64-bit little-endian integer from cursor.
- `bytes_cursor_read_u8(cursor)` - Reads one unsigned byte from cursor.
- `bytes_cursor_seek(cursor, offset)` - Moves cursor to an absolute offset.
- `bytes_cursor_tell(cursor)` - Returns current cursor position.
- `bytes_get(data, index)` - Reads one byte at index as integer.
- `bytes_hex(data)` - Returns uppercase hexadecimal representation of bytes.
- `bytes_int_from_char(char)` - Converts a single-character string to its integer byte value.
- `bytes_len(data)` - Returns length of a bytes value.
- `bytes_read_u16_be(data, offset)` - Reads unsigned 16-bit big-endian integer from bytes at offset.
- `bytes_read_u16_le(data, offset)` - Reads unsigned 16-bit little-endian integer from bytes at offset.
- `bytes_read_u32_be(data, offset)` - Reads unsigned 32-bit big-endian integer from bytes at offset.
- `bytes_read_u32_le(data, offset)` - Reads unsigned 32-bit little-endian integer from bytes at offset.
- `bytes_read_u64_be(data, offset)` - Reads unsigned 64-bit big-endian integer from bytes at offset.
- `bytes_read_u64_le(data, offset)` - Reads unsigned 64-bit little-endian integer from bytes at offset.
- `bytes_slice(data, start, end)` - Returns byte sub-slice from start to end.
- `bytes_write_u16_be(data, offset, value)` - Writes unsigned 16-bit big-endian integer into bytes at offset.
- `bytes_write_u16_le(data, offset, value)` - Writes unsigned 16-bit little-endian integer into bytes at offset.
- `bytes_write_u32_be(data, offset, value)` - Writes unsigned 32-bit big-endian integer into bytes at offset.
- `bytes_write_u32_le(data, offset, value)` - Writes unsigned 32-bit little-endian integer into bytes at offset.
- `bytes_write_u64_be(data, offset, value)` - Writes unsigned 64-bit big-endian integer into bytes at offset.
- `bytes_write_u64_le(data, offset, value)` - Writes unsigned 64-bit little-endian integer into bytes at offset.

## Quick Example

```mutant
let data = fs_read("examples/data/sample_capture.pcap");
let size = len(data)[0];
putln("capture bytes:", size);

let report, err = net_pcap_analyze("examples/data/sample_capture.pcap");
if (err) {
  putln("analyze error:", err);
} else {
  putln(json_stringify(report));
};
```

## Maintenance

When adding/changing language keywords or builtins, update source definitions first and regenerate/review this file.
