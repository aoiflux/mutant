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
	BuiltinNameHelp:  {signature: "help(topic?, mode?)", summary: "Returns help text: an overview, a topic (keywords/builtins/examples/docs), or details for a specific builtin name.", params: []builtinParamDoc{{name: "topic?", doc: "Optional topic or builtin name."}, {name: "mode?", doc: "Optional rendering mode."}}},
	BuiltinNamePutln: {signature: "putln(value)", summary: "Prints a value followed by a newline."},
	BuiltinNamePutf: {
		signature: "putf(format, ...values)",
		summary:   "Formats and prints values using a format string.",
		params: []builtinParamDoc{
			{name: "format", doc: "Printf-style format string."},
			{name: "...values", doc: "Values interpolated into format."},
		},
	},
	BuiltinNameGets:          {signature: "gets()", summary: "Reads a full line of input from stdin and returns it as a STRING (newline trimmed). Use to_int/to_float/parse_int to convert."},
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
	BuiltinNameHttpPost:      {signature: "http_post(url, body, contentType?)", summary: "Performs an HTTP POST request. contentType defaults to application/octet-stream when omitted.", params: []builtinParamDoc{{name: "url", doc: "Absolute request URL."}, {name: "body", doc: "Request body value."}, {name: "contentType?", doc: "Optional Content-Type header (default application/octet-stream)."}}},
	BuiltinNameHttpRequest:   {signature: "http_request(method, url, body, headers)", summary: "Performs an HTTP request with a body and a headers hash. All four arguments are required; the timeout is a fixed 30s (not configurable).", params: []builtinParamDoc{{name: "method", doc: "HTTP verb (GET/POST/etc)."}, {name: "url", doc: "Absolute request URL."}, {name: "body", doc: "Request body value (\"\" for none)."}, {name: "headers", doc: "Hash of request headers."}}},
	BuiltinNameJsonParse:     {signature: "json_parse(text)", summary: "Parses JSON text into Mutant values.", params: []builtinParamDoc{{name: "text", doc: "JSON string input."}}},
	BuiltinNameJsonStringify: {signature: "json_stringify(value)", summary: "Serializes Mutant values into JSON text.", params: []builtinParamDoc{{name: "value", doc: "Value to serialize."}}},
	BuiltinNameLuaRunString:  {signature: "lua_run_string(code)", summary: "Runs a Lua script from a string."},
	BuiltinNameLuaRunFile:    {signature: "lua_run_file(path)", summary: "Runs a Lua script from a file."},
	BuiltinNameLuaRunHttp:    {signature: "lua_run_http(url)", summary: "Fetches and runs a Lua script from an HTTP endpoint in a restricted sandbox (no io, no os.execute/exit/remove; only safe base/math/string/table/os-time libraries)."},
	BuiltinNameStrUpper:      {signature: "str_upper(s)", summary: "Returns s with all letters upper-cased."},
	BuiltinNameStrLower:      {signature: "str_lower(s)", summary: "Returns s with all letters lower-cased."},
	BuiltinNameStrTrim:       {signature: "str_trim(s)", summary: "Returns s with leading and trailing whitespace removed."},
	BuiltinNameStrTrimLeft:   {signature: "str_trim_left(s, cutset)", summary: "Trims any leading characters in cutset from s."},
	BuiltinNameStrTrimRight:  {signature: "str_trim_right(s, cutset)", summary: "Trims any trailing characters in cutset from s."},
	BuiltinNameStrTrimPrefix: {signature: "str_trim_prefix(s, prefix)", summary: "Removes prefix from s if present."},
	BuiltinNameStrTrimSuffix: {signature: "str_trim_suffix(s, suffix)", summary: "Removes suffix from s if present."},
	BuiltinNameStrStartsWith: {signature: "str_starts_with(s, prefix)", summary: "Returns whether s begins with prefix."},
	BuiltinNameStrEndsWith:   {signature: "str_ends_with(s, suffix)", summary: "Returns whether s ends with suffix."},
	BuiltinNameStrJoin:       {signature: "str_join(array, sep)", summary: "Joins an array of strings with sep (inverse of text_split)."},
	BuiltinNameStrRepeat:     {signature: "str_repeat(s, n)", summary: "Returns s repeated n times."},
	BuiltinNameStrPadLeft:    {signature: "str_pad_left(s, width, pad)", summary: "Left-pads s with pad until it reaches width runes."},
	BuiltinNameStrPadRight:   {signature: "str_pad_right(s, width, pad)", summary: "Right-pads s with pad until it reaches width runes."},
	BuiltinNameStrReverse:    {signature: "str_reverse(s)", summary: "Returns s reversed (rune-aware)."},
	BuiltinNameStrSubstr:     {signature: "str_substr(s, start, length)", summary: "Returns length runes of s starting at rune index start (clamped to bounds)."},
	BuiltinNameStrCharAt:     {signature: "str_char_at(s, index)", summary: "Returns the rune at index as a string."},
	BuiltinNameStrFormat:     {signature: "str_format(format, ...values)", summary: "Returns a printf-style formatted string (like putf but returns instead of printing)."},
	BuiltinNameStrTitle:      {signature: "str_title(s)", summary: "Upper-cases the first letter of each word in s."},
	// generic: hashing & IDs
	BuiltinNameHashMD5:    {signature: "hash_md5(s)", summary: "Returns the lowercase hex MD5 digest of s."},
	BuiltinNameHashSHA1:   {signature: "hash_sha1(s)", summary: "Returns the lowercase hex SHA-1 digest of s."},
	BuiltinNameHashSHA256: {signature: "hash_sha256(s)", summary: "Returns the lowercase hex SHA-256 digest of s."},
	BuiltinNameHashSHA512: {signature: "hash_sha512(s)", summary: "Returns the lowercase hex SHA-512 digest of s."},
	BuiltinNameHashCRC32:  {signature: "hash_crc32(s)", summary: "Returns the CRC-32 (IEEE) checksum of s as 8 hex chars."},
	BuiltinNameHashBlake2: {signature: "hash_blake2(s)", summary: "Returns the lowercase hex BLAKE2b-256 digest of s."},
	BuiltinNameHMAC:       {signature: "hmac(key, message, algo)", summary: "Returns the hex HMAC of message under key. algo is md5/sha1/sha256/sha512.", params: []builtinParamDoc{{name: "key", doc: "Secret key."}, {name: "message", doc: "Message to authenticate."}, {name: "algo", doc: "Hash algorithm: md5/sha1/sha256/sha512."}}},
	BuiltinNameUUIDv4:     {signature: "uuid_v4()", summary: "Returns a random (v4) UUID string."},
	BuiltinNameUUIDv7:     {signature: "uuid_v7()", summary: "Returns a time-ordered (v7) UUID string."},
	BuiltinNameRandomHex:  {signature: "random_hex(n)", summary: "Returns n cryptographically-random bytes as a 2n-char hex string."},
	BuiltinNameNanoID:     {signature: "nanoid(n)", summary: "Returns a URL-safe random identifier of length n."},
	// generic: math
	BuiltinNameAbs:       {signature: "abs(x)", summary: "Absolute value (preserves INTEGER/FLOAT type)."},
	BuiltinNameMin:       {signature: "min(...values)", summary: "Returns the smallest of the numeric arguments (original type preserved)."},
	BuiltinNameMax:       {signature: "max(...values)", summary: "Returns the largest of the numeric arguments (original type preserved)."},
	BuiltinNameClamp:     {signature: "clamp(x, lo, hi)", summary: "Constrains x to the range [lo, hi]."},
	BuiltinNamePow:       {signature: "pow(x, y)", summary: "Returns x raised to the power y (FLOAT)."},
	BuiltinNameSqrt:      {signature: "sqrt(x)", summary: "Returns the square root of x (FLOAT); errors on negative x."},
	BuiltinNameMod:       {signature: "mod(a, b)", summary: "Returns a modulo b; errors on b=0. Integer mod when both are INTEGER."},
	BuiltinNameFloor:     {signature: "floor(x)", summary: "Largest integer <= x (INTEGER)."},
	BuiltinNameCeil:      {signature: "ceil(x)", summary: "Smallest integer >= x (INTEGER)."},
	BuiltinNameRound:     {signature: "round(x)", summary: "Nearest integer to x (INTEGER)."},
	BuiltinNameSum:       {signature: "sum(array)", summary: "Sum of a numeric array (INTEGER if all elements are integers)."},
	BuiltinNameAvg:       {signature: "avg(array)", summary: "Arithmetic mean of a numeric array (FLOAT); errors on empty."},
	BuiltinNameRand:      {signature: "rand()", summary: "Returns a random FLOAT in [0, 1)."},
	BuiltinNameRandInt:   {signature: "rand_int(lo, hi)", summary: "Returns a random INTEGER in [lo, hi)."},
	BuiltinNameRandBytes: {signature: "rand_bytes(n)", summary: "Returns n cryptographically-random bytes (as a byte string)."},
	BuiltinNameMathPi:    {signature: "math_pi()", summary: "Returns the constant pi."},
	BuiltinNameMathE:     {signature: "math_e()", summary: "Returns the constant e."},
	// generic: encoding (decoders return (value, err))
	BuiltinNameBase64Encode:    {signature: "base64_encode(s)", summary: "Standard base64-encodes s."},
	BuiltinNameBase64Decode:    {signature: "base64_decode(s)", summary: "Decodes standard base64; returns (bytes, err)."},
	BuiltinNameBase64URLEncode: {signature: "base64url_encode(s)", summary: "URL-safe base64-encodes s."},
	BuiltinNameBase64URLDecode: {signature: "base64url_decode(s)", summary: "Decodes URL-safe base64; returns (bytes, err)."},
	BuiltinNameBase32Encode:    {signature: "base32_encode(s)", summary: "Standard base32-encodes s."},
	BuiltinNameBase32Decode:    {signature: "base32_decode(s)", summary: "Decodes standard base32; returns (bytes, err)."},
	BuiltinNameHexEncode:       {signature: "hex_encode(s)", summary: "Hex-encodes a byte string to lowercase hex."},
	BuiltinNameHexDecode:       {signature: "hex_decode(s)", summary: "Decodes a hex string to bytes; returns (bytes, err)."},
	BuiltinNameURLEncode:       {signature: "url_encode(s)", summary: "URL query-escapes s."},
	BuiltinNameURLDecode:       {signature: "url_decode(s)", summary: "URL query-unescapes s; returns (value, err)."},
	BuiltinNameGzip:            {signature: "gzip(s)", summary: "Gzip-compresses s (returns a byte string)."},
	BuiltinNameGunzip:          {signature: "gunzip(s)", summary: "Gzip-decompresses s; returns (bytes, err)."},
	BuiltinNameZlibCompress:    {signature: "zlib_compress(s)", summary: "Zlib-compresses s (returns a byte string)."},
	BuiltinNameZlibDecompress:  {signature: "zlib_decompress(s)", summary: "Zlib-decompresses s; returns (bytes, err)."},
	BuiltinNameToBase:          {signature: "to_base(n, base)", summary: "Formats integer n in the given base (2–36)."},
	BuiltinNameFromBase:        {signature: "from_base(s, base)", summary: "Parses s as an integer in the given base (2–36); returns (int, err)."},
	// generic: type conversion & introspection
	BuiltinNameToInt:      {signature: "to_int(v)", summary: "Converts a number/bool/string to INTEGER; returns (int, err)."},
	BuiltinNameToFloat:    {signature: "to_float(v)", summary: "Converts a number/bool/string to FLOAT; returns (float, err)."},
	BuiltinNameToString:   {signature: "to_string(v)", summary: "Converts any value to its STRING representation."},
	BuiltinNameToBool:     {signature: "to_bool(v)", summary: "Converts a bool/number/string to BOOLEAN; returns (bool, err)."},
	BuiltinNameParseInt:   {signature: "parse_int(s, base)", summary: "Parses s as an integer in base (0 auto-detects); returns (int, err)."},
	BuiltinNameParseFloat: {signature: "parse_float(s)", summary: "Parses s as a float; returns (float, err)."},
	BuiltinNameTypeOf:     {signature: "type_of(v)", summary: "Returns the object type name of v (e.g. INTEGER, STRING, ARRAY)."},
	BuiltinNameIsNull:     {signature: "is_null(v)", summary: "Returns whether v is NULL."},
	// generic: time & date (epoch seconds; Go reference layout, e.g. \"2006-01-02 15:04:05\")
	BuiltinNameTimeNow:    {signature: "time_now()", summary: "Returns the current UTC time as a hash {unix, iso, year, month, day, hour, minute, second}."},
	BuiltinNameTimeUnix:   {signature: "time_unix()", summary: "Returns the current Unix time in seconds."},
	BuiltinNameTimeFormat: {signature: "time_format(unix, layout)", summary: "Formats a Unix timestamp (UTC) using a Go reference layout."},
	BuiltinNameTimeParse:  {signature: "time_parse(value, layout)", summary: "Parses value with a Go reference layout; returns (unixSeconds, err)."},
	BuiltinNameTimeDiff:   {signature: "time_diff(a, b)", summary: "Returns a - b in seconds (both Unix timestamps)."},
	BuiltinNameTimeAdd:    {signature: "time_add(unix, seconds)", summary: "Returns the Unix timestamp shifted by seconds."},
	// generic: collections (array + hash operations; return new values, never mutate)
	BuiltinNameSort:         {signature: "sort(array)", summary: "Returns a sorted copy of an array (all numbers or all strings)."},
	BuiltinNameReverseArray: {signature: "reverse(array)", summary: "Returns a reversed copy of an array."},
	BuiltinNameContains:     {signature: "contains(array, value)", summary: "Returns whether array contains value (by value equality)."},
	BuiltinNameIndexOf:      {signature: "index_of(array, value)", summary: "Returns the first index of value in array, or -1."},
	BuiltinNameSlice:        {signature: "slice(array, start, end)", summary: "Returns the sub-array array[start:end] (bounds-clamped)."},
	BuiltinNameConcat:       {signature: "concat(a, b)", summary: "Returns a new array with the elements of a followed by b."},
	BuiltinNameFlatten:      {signature: "flatten(array)", summary: "Flattens one level of nested arrays."},
	BuiltinNameUnique:       {signature: "unique(array)", summary: "Returns a new array with duplicate values removed (order preserved)."},
	BuiltinNameRange:        {signature: "range(start, end, step?)", summary: "Returns an array of integers from start (inclusive) to end (exclusive); step defaults to 1."},
	BuiltinNameZip:          {signature: "zip(a, b)", summary: "Returns an array of [a[i], b[i]] pairs up to the shorter length."},
	BuiltinNameKeys:         {signature: "keys(hash)", summary: "Returns the hash keys as an array (sorted for determinism)."},
	BuiltinNameValues:       {signature: "values(hash)", summary: "Returns the hash values as an array (ordered by sorted key)."},
	BuiltinNameEntries:      {signature: "entries(hash)", summary: "Returns the hash as an array of [key, value] pairs (sorted by key)."},
	BuiltinNameHasKey:       {signature: "has_key(hash, key)", summary: "Returns whether hash contains key."},
	BuiltinNameGet:          {signature: "get(hash, key, default)", summary: "Returns hash[key], or default when the key is absent."},
	BuiltinNameSet:          {signature: "set(hash, key, value)", summary: "Returns a new hash with key set to value (original unchanged)."},
	BuiltinNameMerge:        {signature: "merge(a, b)", summary: "Returns a new hash combining a and b (b wins on key conflicts)."},
	BuiltinNameDelete:       {signature: "delete(hash, key)", summary: "Returns a new hash with key removed."},
	// security: Go binary analysis (GoReSym) — parses PE/ELF/Mach-O Go binaries
	BuiltinNameGoBuildInfo: {signature: "go_buildinfo(path)", summary: "Extracts Go build info from a binary: go_version, module path, main module, dependencies (path/version/sum), and build settings (GOOS/GOARCH/vcs.*). Returns (info, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a Go-compiled binary (PE/ELF/Mach-O)."}}},
	BuiltinNameGoBuildID:   {signature: "go_build_id(path)", summary: "Extracts the Go build ID from a binary. Returns (build_id, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a Go-compiled binary."}}},
	BuiltinNameGoSymbols:   {signature: "go_symbols(path, mode?)", summary: "Recovers function symbols from a Go binary via the pclntab — works even on STRIPPED binaries. Returns {go_version, arch, os, pclntab_va, function_count, user_function_count, std_function_count, functions:[{name, package, start, end, stdlib}]}. mode is \"all\" (default), \"user\", or \"std\". Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a Go-compiled binary."}, {name: "mode?", doc: "Filter: all/user/std (default all)."}}},
	// security: IOC / network intelligence
	BuiltinNameDefang:        {signature: "defang(ioc)", summary: "Defangs an indicator for safe display (http->hxxp, .->[.], @->[at])."},
	BuiltinNameRefang:        {signature: "refang(ioc)", summary: "Reverses common defang encodings ([.]/(.)/[dot]->., hxxp->http, [at]->@)."},
	BuiltinNameIPIsPrivate:   {signature: "ip_is_private(ip)", summary: "Returns whether an IP is private/loopback/link-local (RFC1918 etc.)."},
	BuiltinNameIPInCIDR:      {signature: "ip_in_cidr(ip, cidr)", summary: "Returns whether an IP falls within a CIDR range.", params: []builtinParamDoc{{name: "ip", doc: "IPv4 or IPv6 address."}, {name: "cidr", doc: "CIDR network, e.g. 10.0.0.0/8."}}},
	BuiltinNameCIDRHosts:     {signature: "cidr_hosts(cidr)", summary: "Returns all addresses in a CIDR range (capped; errors if >20 host bits)."},
	BuiltinNameIPVersion:     {signature: "ip_version(ip)", summary: "Returns 4, 6, or 0 (invalid) for an IP address."},
	BuiltinNameIPToInt:       {signature: "ip_to_int(ip)", summary: "Converts an IPv4 address to its 32-bit integer form."},
	BuiltinNameIntToIP:       {signature: "int_to_ip(n)", summary: "Converts a 32-bit integer to an IPv4 dotted-quad string."},
	BuiltinNameDomainExtract: {signature: "domain_extract(url)", summary: "Extracts the lowercased hostname from a URL or host string."},
	BuiltinNameTLDExtract:    {signature: "tld_extract(domain)", summary: "Returns {domain, etld1, suffix} using the public suffix list."},
	BuiltinNameIsValidDomain: {signature: "is_valid_domain(s)", summary: "Returns whether s is a syntactically valid domain name."},
	BuiltinNameExtractIOCs:   {signature: "extract_iocs(text)", summary: "Extracts IOCs from text (refanged first): {ipv4, urls, domains, emails, md5, sha1, sha256}, each unique and sorted."},
	// forensic: hash sets (known-file filtering, NSRL-style)
	BuiltinNameHashsetLoad:     {signature: "hashset_load(path)", summary: "Loads a file of hashes (one per line, or CSV/NSRL where the hash is the first field) into an in-memory set. Skips headers/comments/non-hex. Returns {handle, count}. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a hash list (md5/sha1/sha256 hex)."}}},
	BuiltinNameHashsetContains: {signature: "hashset_contains(handle, hash)", summary: "Returns whether a hash is in a loaded set (case-insensitive). Returns (bool, err).", params: []builtinParamDoc{{name: "handle", doc: "Handle from hashset_load."}, {name: "hash", doc: "Hex hash to look up."}}},
	BuiltinNameHashsetClose:    {signature: "hashset_close(handle)", summary: "Frees a loaded hash set. Returns (bool, err)."},
	// forensic: timeline
	BuiltinNameTimestampNormalize: {signature: "timestamp_normalize(value, format?)", summary: "Normalizes a timestamp to {unix, unix_ms, iso, format}. Formats: unix (s/ms/us/ns), filetime (Windows), webkit/chrome, dos (packed 32-bit), iso (RFC3339 string). Default \"auto\" detects unix magnitude or parses an ISO string. Returns (result, err).", params: []builtinParamDoc{{name: "value", doc: "INTEGER epoch/packed value, or ISO STRING."}, {name: "format?", doc: "One of auto/unix/unix_ms/unix_us/unix_ns/filetime/webkit/dos/iso."}}},
	BuiltinNameTimelineSort:       {signature: "timeline_sort(events, field?)", summary: "Returns events (array of hashes) sorted ascending by a numeric timestamp field (default \"ts\"); events missing the field sort last. Stable."},
	BuiltinNameTimelineMerge:      {signature: "timeline_merge(sources, field?)", summary: "Flattens an array of event arrays into one supertimeline sorted by a numeric timestamp field (default \"ts\")."},
	BuiltinNameBodyfileParse:      {signature: "bodyfile_parse(path)", summary: "Parses a Sleuth Kit bodyfile (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime) into an array of entry hashes. Returns (entries, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a TSK bodyfile."}}},
	BuiltinNamePlistParse:         {signature: "plist_parse(path)", summary: "Parses an Apple property list (binary bplist00 or XML) into a Mutant value: dict->hash, array->array, string/integer/real/bool as scalars; dates and data become strings. Returns (value, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a .plist file (binary or XML)."}}},
	BuiltinNameHiveOpen:       {signature: "hive_open(path)", summary: "Opens a real Windows registry hive (regf binary format — SOFTWARE/SYSTEM/NTUSER.DAT, etc.) and returns {handle, path}. Distinct from the JSON-fixture reg_* family. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a registry hive file."}}},
	BuiltinNameHiveClose:      {signature: "hive_close(handle)", summary: "Closes a hive handle. Returns (bool, err)."},
	BuiltinNameHiveKeyInfo:    {signature: "hive_key_info(handle, keypath?)", summary: "Returns {name, last_write, last_write_iso, subkey_count, value_count} for a key (keypath is backslash-separated under the root; default root). Returns (result, err)."},
	BuiltinNameHiveListKeys:   {signature: "hive_list_keys(handle, keypath?)", summary: "Returns the subkey names under a key (default root) as an array. Returns (array, err)."},
	BuiltinNameHiveListValues: {signature: "hive_list_values(handle, keypath?)", summary: "Returns a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Returns (array, err)."},
	BuiltinNameHiveGetValue:   {signature: "hive_get_value(handle, keypath, name)", summary: "Returns {name, type, data} for a single value under keypath. Returns (result, err)."},
	BuiltinNameShimcacheParse: {signature: "shimcache_parse(path)", summary: "Decodes the Windows AppCompatCache (shimcache) — program execution/presence evidence. Accepts a SYSTEM hive file (locates the value) or a raw AppCompatCache blob. Supports Win8/Win8.1/Win10 (10ts/00ts). Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "SYSTEM hive file or raw AppCompatCache blob."}}},
	BuiltinNameAmcacheParse:   {signature: "amcache_parse(path)", summary: "Parses an Amcache.hve hive (program execution/presence evidence) into {format, count, entries:[{key, path, name, sha1, publisher, version, product, size, last_write}]}. Supports the modern InventoryApplicationFile and legacy Root\\File layouts. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to an Amcache.hve hive file."}}},
	BuiltinNamePrefetchParse:  {signature: "prefetch_parse(path)", summary: "Decodes a Windows Prefetch (.pf) file — program execution evidence. Transparently decompresses the Win10/11 MAM (Xpress-Huffman) container and parses the SCCA format for XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31). Returns {version, executable, prefetch_hash, run_count, run_times[], files_loaded[], file_count, volumes:[{device_path, serial, created, created_iso}], compressed}. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a .pf prefetch file (compressed or raw SCCA)."}}},
	BuiltinNameMftParse:       {signature: "mft_parse(path)", summary: "Parses an NTFS Master File Table into a per-record timeline. Auto-detects a standalone $MFT file (FILE-signature record stream, e.g. KAPE/FTK/icat) vs a full NTFS volume image. Each entry has $STANDARD_INFORMATION and $FILE_NAME MAC times (unix + iso), reconstructed path, size, sequence, and hard-link count. Returns {source_type, record_size, count, entries:[{record, parent_record, in_use, is_directory, name, path, size, allocated_size, sequence, hard_links, file_attributes, si_*, fn_*}]}. Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a standalone $MFT file or an NTFS volume image."}}},
	BuiltinNameLnkParse:           {signature: "lnk_parse(path)", summary: "Parses a Windows shell link (.lnk): header (attributes, creation/access/write FILETIME->unix), decoded LinkFlags, LinkInfo local_base_path (target), and StringData (name, relative_path, working_dir, arguments, icon_location). Returns (result, err).", params: []builtinParamDoc{{name: "path", doc: "Path to a .lnk shell link file."}}},
	BuiltinNameMactime:            {signature: "mactime(entries)", summary: "Builds a chronological MAC-time timeline from bodyfile_parse entries: one row per distinct time with a MACB flag string (m/a/c/b, \".\" where absent), sorted by ts then name (ts field composes with timeline_merge)."},
	// security: fingerprinting
	BuiltinNameImphash: {signature: "imphash(pe_path)", summary: "Computes the PE import hash (pefile/Mandiant algorithm) for malware clustering. Returns {imphash, import_count, dll_count}. Note: ordinal-only imports are rendered as ord<N>, so results may differ from VT for ws2_32/oleaut32 ordinal imports. Returns (result, err).", params: []builtinParamDoc{{name: "pe_path", doc: "Path to a PE (Windows) binary."}}},
	BuiltinNameNTHash:  {signature: "nt_hash(password)", summary: "Returns the NTLM NT hash (MD4 of the UTF-16LE password) as hex. For authorized credential testing/CTF use."},
	BuiltinNameLMHash:  {signature: "lm_hash(password)", summary: "Returns the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex. Empty password -> aad3b435b51404eeaad3b435b51404ee."},
	// security: crypto
	BuiltinNameX509Parse:  {signature: "x509_parse(pem_or_der)", summary: "Parses an X.509 certificate (PEM or DER). Returns {subject, issuer, serial, not_before, not_after, is_ca, version, dns_names, ip_addresses, email_addresses, key_algorithm, signature_algorithm, sha1, sha256}. Returns (cert, err).", params: []builtinParamDoc{{name: "pem_or_der", doc: "Certificate bytes in PEM or DER form."}}},
	BuiltinNameJWTDecode:  {signature: "jwt_decode(token)", summary: "Decodes a JWT's header and claims WITHOUT verifying the signature (verified is always false). Returns {header, claims, algorithm, signature_present, verified}. Returns (result, err).", params: []builtinParamDoc{{name: "token", doc: "Compact JWT string (header.payload.signature)."}}},
	BuiltinNameAESEncrypt: {signature: "aes_encrypt(key, plaintext)", summary: "AES-GCM encrypts plaintext. key must be 16/24/32 bytes. A random nonce is prepended to the output. Returns (ciphertext, err).", params: []builtinParamDoc{{name: "key", doc: "16/24/32-byte key (AES-128/192/256)."}, {name: "plaintext", doc: "Data to encrypt."}}},
	BuiltinNameAESDecrypt: {signature: "aes_decrypt(key, ciphertext)", summary: "AES-GCM decrypts ciphertext produced by aes_encrypt (nonce-prefixed). Returns (plaintext, err); errors on wrong key or tampering.", params: []builtinParamDoc{{name: "key", doc: "16/24/32-byte key."}, {name: "ciphertext", doc: "Nonce-prefixed AES-GCM ciphertext."}}},
	BuiltinNamePEMDecode:  {signature: "pem_decode(s)", summary: "Decodes the first PEM block. Returns {type, headers, der_hex, size, remaining_bytes}. Returns (result, err)."},
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
	BuiltinNameProcessList: {signature: "process_list()", summary: "Lists running processes (pid, ppid, name) natively on Windows, Linux, and macOS."},
	BuiltinNameProcessTree: {
		signature: "process_tree(rootPid?)",
		summary:   "Returns descendant processes for a root pid (default current process). Cross-platform, using real parent PIDs on every OS.",
		params:    []builtinParamDoc{{name: "rootPid?", doc: "Optional root process ID; defaults to current process."}},
	},
	BuiltinNameProcessOpenFiles: {
		signature: "process_open_files(pid?)",
		summary:   "Lists open file paths for a process (cross-platform; may require privileges for other processes).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessThreads: {
		signature: "process_threads(pid?)",
		summary:   "Returns {pid, count, tids} for a process. The thread count is cross-platform; tids are populated where the OS exposes them (e.g. Linux).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessModules: {
		signature: "process_modules(pid?)",
		summary:   "Lists loaded module/library paths for a process (memory maps on Linux, Toolhelp32 on Windows; fails honestly on platforms without a backend, e.g. macOS).",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessHash: {
		signature: "process_hash(pid?)",
		summary:   "Computes SHA-256 hash metadata for a process executable.",
		params:    []builtinParamDoc{{name: "pid?", doc: "Optional process ID; defaults to current process."}},
	},
	BuiltinNameProcessMemoryScan: {
		signature: "process_memory_scan(pid, pattern)",
		summary:   "Scans a process's readable memory for a byte pattern and returns {pid, pattern, matched, truncated, addresses}. Real scan on Linux (/proc/self/mem) and Windows (VirtualQuery+ReadProcessMemory); self process only for now; honest error on macOS.",
		params: []builtinParamDoc{
			{name: "pid", doc: "Target process ID (must be the current process for now)."},
			{name: "pattern", doc: "Non-empty byte pattern to search for."},
		},
	},
	BuiltinNameProcessEnv: {
		signature: "process_env(pid?)",
		summary:   "Returns environment variables for a process (cross-platform; other processes may require privileges).",
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
		summary:   "Compares two files (not directories) and reports differences.",
	},
	BuiltinNameFsCarve: {
		signature: "fs_carve(path, type)",
		summary:   "Scans a file for a known artifact signature and returns the byte offsets where it starts. It reports offsets only; it does not extract (carve out) the artifact bytes or determine their length.",
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
		signature: "bin_yara_scan(path, rules, caseInsensitive?)",
		summary:   "Literal multi-string scan of a file (NOT a real YARA engine — that needs cgo). Reports every offset of each rule string. Case-sensitive unless caseInsensitive is true. Returns {engine, matched, total_hits, hits:[{rule, count, offsets}]}.",
		params: []builtinParamDoc{
			{name: "path", doc: "Path to the file to scan."},
			{name: "rules", doc: "Array of literal STRING patterns."},
			{name: "caseInsensitive?", doc: "Optional BOOLEAN; default false (case-sensitive)."},
		},
	},
	BuiltinNameBinImports: {
		signature: "bin_imports(path)",
		summary:   "Returns imported symbols/libraries from a binary.",
	},
	BuiltinNameBinSections: {
		signature: "bin_sections(path)",
		summary:   "Returns binary section table information.",
	},
	BuiltinNameNetSynScan: {signature: "net_syn_scan(host, startPort, endPort, timeoutMs)", summary: "Scans a TCP port range on a host. NOTE: this is a full TCP connect scan, not a half-open SYN scan.", params: []builtinParamDoc{{name: "host", doc: "Target host."}, {name: "startPort", doc: "First port (inclusive)."}, {name: "endPort", doc: "Last port (inclusive)."}, {name: "timeoutMs", doc: "Per-port connect timeout in ms."}}},
	BuiltinNameNetUdpScan: {signature: "net_udp_scan(host, startPort, endPort, timeoutMs)", summary: "Scans a UDP port range on a host.", params: []builtinParamDoc{{name: "host", doc: "Target host."}, {name: "startPort", doc: "First port (inclusive)."}, {name: "endPort", doc: "Last port (inclusive)."}, {name: "timeoutMs", doc: "Per-port timeout in ms."}}},
	BuiltinNameNetBanner:  {signature: "net_banner(address, timeoutMs)", summary: "Collects service banner text from a network endpoint.", params: []builtinParamDoc{{name: "address", doc: "host:port endpoint."}, {name: "timeoutMs", doc: "Read timeout in ms."}}},
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
		signature: "net_os_fingerprint(pcap_path)",
		summary:   "Passively fingerprints OS families from TCP SYN/SYN-ACK packets in an offline pcap (p0f-style heuristic over TTL, DF, window, and TCP options). Identifies an OS family, not a definitive OS; runs offline with no privileges.",
		params: []builtinParamDoc{
			{name: "pcap_path", doc: "Path to a pcap file to analyze."},
		},
	},
	BuiltinNameRegOpen: {
		signature: "reg_open(source)",
		summary:   "Opens a registry data source (polymorphic) and returns {handle, path, source_type, status}. Dispatch: a regf hive file (SOFTWARE/SYSTEM/NTUSER.DAT, …) -> real hive parse; a hive-JSON file -> JSON; otherwise a live Windows registry path (e.g. HKLM\\SOFTWARE\\...) -> live registry (Windows only). Returns (result, err).",
		params:    []builtinParamDoc{{name: "source", doc: "regf hive file, hive-JSON file, or live registry key path (HKLM/HKCU/HKCR/HKU/HKCC)."}},
	},
	BuiltinNameRegEnumKeys: {
		signature: "reg_enum_keys(handle, keyPath?)",
		summary:   "Enumerates subkeys under a key. For hive/live sources keyPath is relative to the opened key (default root); for JSON it is the absolute path. Returns (array, err).",
		params: []builtinParamDoc{
			{name: "handle", doc: "Handle returned by reg_open."},
			{name: "keyPath?", doc: "Subkey path (default: the opened key/root)."},
		},
	},
	BuiltinNameRegEnumValues: {
		signature: "reg_enum_values(handle, keyPath?)",
		summary:   "Enumerates a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Works across JSON/hive-file/live sources. Returns (array, err).",
		params: []builtinParamDoc{
			{name: "handle", doc: "Handle returned by reg_open."},
			{name: "keyPath?", doc: "Key path (default: the opened key/root)."},
		},
	},
	BuiltinNameRegGetValue: {
		signature: "reg_get_value(handle, keyPath, valueName)",
		summary:   "Reads a specific registry value with type metadata, across JSON/hive-file/live sources. Returns (result, err).",
		params: []builtinParamDoc{
			{name: "handle", doc: "Handle returned by reg_open."},
			{name: "keyPath", doc: "Key path that contains the value."},
			{name: "valueName", doc: "Registry value name to fetch."},
		},
	},
	BuiltinNameRegDeletedKeys: {
		signature: "reg_deleted_keys(handle)",
		summary:   "Lists deleted-key entries. Populated only for the JSON source (its deleted_keys field); empty for real hive files and live registry (no unallocated-cell carving).",
	},
	BuiltinNameRegTimeline: {
		signature: "reg_timeline(handle)",
		summary:   "Returns timeline entries. Populated only for the JSON source (its timeline field); empty for real hive files and live registry.",
		params:    []builtinParamDoc{{name: "handle", doc: "Handle returned by reg_open."}},
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
		summary:   "Cryptographically verifies DKIM signatures (public key via DNS) and reports SPF/DMARC. SPF is reported as recorded by the receiving MTA; DMARC combines the reported result with DKIM alignment.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameEmailUrls: {
		signature: "email_urls(raw)",
		summary:   "Extracts and normalizes URLs from email headers and body.",
		params:    []builtinParamDoc{{name: "raw", doc: "RFC822-style raw email text."}},
	},
	BuiltinNameMemMap: {
		signature: "mem_map(path)",
		summary:   "Splits a memory dump into fixed-size (4 KiB) segments, each with measured entropy and printable-byte ratio. A raw dump carries no page-protection metadata, so no readable/writable/executable flags are reported.",
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
		summary:   "Finds PE headers in a memory image: carves each MZ marker and confirms real PEs by following e_lfanew to \"PE\\0\\0\". Returns {candidates, confirmed, headers:[{mz_offset, confirmed, pe_offset, machine}]}.",
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
		summary:   "Scores probable code injection in a memory image using multiple PE headers plus weighted shellcode signatures (GetPC via fnstenv/call-pop, PEB walks, NOP sleds); returns score and matched_signatures.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash containing evidence such as mem_path."}},
	},
	BuiltinNameDetectNetworkBeacon: {
		signature: "detect_network_beacon(flows)",
		summary:   "Detects C2 beaconing by analyzing inter-arrival interval regularity (low coefficient of variation) and optional transfer-size consistency per destination; each flow may carry ts (epoch/RFC3339) and bytes. Returns per-dst score, interval_cv, and confidence.",
		params:    []builtinParamDoc{{name: "flows", doc: "Array of flow hashes with a dst, and optional ts and bytes fields."}},
	},
	BuiltinNameDetectPrivEsc: {
		signature: "detect_priv_esc(facts)",
		summary:   "Detects potential privilege-escalation indicators from host facts.",
		params:    []builtinParamDoc{{name: "facts", doc: "Hash of privilege-related evidence and boolean checks."}},
	},
	BuiltinNameDetectSuspiciousFiles: {
		signature: "detect_suspicious_files(paths)",
		summary:   "Flags suspicious files via entropy tiers (high/very-high), executable magic under a document extension (extension_mismatch), and disguised double extensions (e.g. invoice.pdf.exe).",
		params:    []builtinParamDoc{{name: "paths", doc: "Array of filesystem paths to inspect."}},
	},
	BuiltinNameNetResolve:        {signature: "net_resolve(host)", summary: "Resolves a host name to network addresses."},
	BuiltinNameNetDial:           {signature: "net_dial(address, timeoutMs)", summary: "Connectivity probe: dials address, immediately closes, and returns {ok, latency_ms, error}. Does not return a usable connection (use net_connect for that).", params: []builtinParamDoc{{name: "address", doc: "host:port endpoint."}, {name: "timeoutMs", doc: "Dial timeout in ms."}}},
	BuiltinNameDbOpen:            {signature: "db_open()", summary: "Creates an in-memory graph database handle."},
	BuiltinNameDbOpenDisk:        {signature: "db_open_disk(path)", summary: "Opens or creates a disk-backed graph database.", params: []builtinParamDoc{{name: "path", doc: "Database file path."}}},
	BuiltinNameDbClose:           {signature: "db_close(db)", summary: "Closes a graph database handle and flushes pending state.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameDbAddNode:         {signature: "db_add_node(db, nodeType?)", summary: "Adds a DATA node and returns its ID. nodeType is an optional integer/enum node type (0–127). Property hashes are not supported.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "nodeType?", doc: "Optional integer/enum node type (0–127)."}}},
	BuiltinNameDbAddEdge:         {signature: "db_add_edge(db, from, to, edgeType?)", summary: "Adds an edge between two node IDs. edgeType is an optional integer/enum edge type. Edge property hashes are not supported.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}, {name: "edgeType?", doc: "Optional integer/enum edge type."}}},
	BuiltinNameDbAddArtifact:     {signature: "db_add_artifact(db, type, attrs?)", summary: "Adds a forensic artifact node. type is a STRING; attrs is an optional properties hash that is indexed.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "type", doc: "Artifact type string."}, {name: "attrs?", doc: "Optional attributes hash (indexed)."}}},
	BuiltinNameDbAddRelation:     {signature: "db_add_relation(db, from, to, relation)", summary: "Adds a named relation edge between two entity IDs. All four arguments are required; property hashes are not supported.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source entity ID."}, {name: "to", doc: "Destination entity ID."}, {name: "relation", doc: "Relation type string."}}},
	BuiltinNameDbIndexProp:       {signature: "db_index_prop(db, nodeID, key, value)", summary: "Indexes a property (key=value) on a node. All four arguments are required.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "nodeID", doc: "Node ID to index."}, {name: "key", doc: "Property key."}, {name: "value", doc: "Property value."}}},
	BuiltinNameDbQueryNodes:      {signature: "db_query_nodes(db, nodeType?)", summary: "Returns node IDs, optionally filtered to a single node type (integer/enum).", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "nodeType?", doc: "Optional integer/enum node type filter."}}},
	BuiltinNameDbQuery:           {signature: "db_query(db)", summary: "Returns all DATA-type node IDs (an alias for db_query_nodes with no type filter). There is no query-expression language.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameDbBfs:             {signature: "db_bfs(db, origin, depth, direction)", summary: "Breadth-first traversal from origin up to depth. direction is \"in\", \"out\", or \"both\". All four arguments are required.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "origin", doc: "Origin node ID."}, {name: "depth", doc: "Maximum traversal depth."}, {name: "direction", doc: "Edge direction: \"in\", \"out\", or \"both\"."}}},
	BuiltinNameDbShortestPath:    {signature: "db_shortest_path(db, from, to)", summary: "Computes shortest path between two graph nodes.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}, {name: "from", doc: "Source node ID."}, {name: "to", doc: "Destination node ID."}}},
	BuiltinNameDbTimeline:        {signature: "db_timeline(db)", summary: "Returns chronological timeline events recorded in the graph. Takes only the handle (no options argument).", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameDbStats:           {signature: "db_stats(db)", summary: "Returns graph database statistics.", params: []builtinParamDoc{{name: "db", doc: "Database handle."}}},
	BuiltinNameBytesLen:          {signature: "bytes_len(data)", summary: "Returns length of a bytes value."},
	BuiltinNameBytesGet:          {signature: "bytes_get(data, index)", summary: "Reads one byte at index as integer."},
	BuiltinNameBytesSlice:        {signature: "bytes_slice(data, start, length)", summary: "Returns a byte sub-slice of the given length starting at start (i.e. data[start:start+length]).", params: []builtinParamDoc{{name: "data", doc: "Source byte string."}, {name: "start", doc: "Start offset."}, {name: "length", doc: "Number of bytes to take."}}},
	BuiltinNameBytesHex:          {signature: "bytes_hex(value, width)", summary: "Formats an integer as a zero-padded uppercase hex string with a 0x prefix (e.g. bytes_hex(4660, 8) -> \"0x00001234\"). This formats a number; it does not hex-encode a byte string.", params: []builtinParamDoc{{name: "value", doc: "Integer value to format."}, {name: "width", doc: "Minimum hex digit width (zero-padded)."}}},
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
		summary:   "Reads up to maxBytes from a connection; returns {data, bytes, eof, error} with I/O failures in the error field.",
		params:    []builtinParamDoc{{name: "handle", doc: "Connection handle."}, {name: "maxBytes", doc: "Maximum bytes to read (1..32 MiB)."}, {name: "timeoutMs", doc: "Read timeout in ms (0 = block)."}},
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
	BuiltinNameNetServe:       {signature: "net_serve(listener, handler_path, arg?)", summary: "Accept loop that dispatches each connection to a fresh VM running handler_path; handler reads its connection via serve_conn() and shared arg via serve_arg(). Concurrent."},
	BuiltinNameNetSpawn:       {signature: "net_spawn(handler_path, arg?)", summary: "Runs handler_path on a new goroutine with no connection (serve_conn()->0) and arg via serve_arg(). For auxiliary workers, e.g. a WebSocket reverse pump."},
	BuiltinNameServeConn:      {signature: "serve_conn()", summary: "Inside a net_serve handler, returns the connection handle (INTEGER); null otherwise."},
	BuiltinNameServeArg:       {signature: "serve_arg()", summary: "Inside a net_serve handler, returns the shared arg passed to net_serve; null otherwise."},
	BuiltinNameSleepMs:        {signature: "sleep_ms(ms)", summary: "Blocks the current handler for ms milliseconds."},
	BuiltinNameTimeMs:         {signature: "time_ms()", summary: "Returns the current Unix time in milliseconds."},
	BuiltinNameWsAcceptKey:    {signature: "ws_accept_key(client_key)", summary: "Computes the Sec-WebSocket-Accept value for an RFC 6455 101 handshake response."},
	BuiltinNameWsReadFrame:    {signature: "ws_read_frame(handle, timeoutMs)", summary: "Reads one WebSocket frame (unmasked); returns {fin, opcode, payload, masked, length, is_control}."},
	BuiltinNameWsWriteFrame:   {signature: "ws_write_frame(handle, opcode, payload, mask)", summary: "Writes one WebSocket frame; mask=true for client->server, false for server->client."},
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
			{name: "options?", doc: "Hash: server_name, insecure, alpn, min_version, ca_cert, client_cert, client_key, handshake_timeout_ms."},
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
	BuiltinNameHttpParseRequest:         {signature: "http_parse_request(raw)", summary: "Parses a raw HTTP request into {method, url, path, host, proto, query, headers, body}."},
	BuiltinNameHttpParseResponse:        {signature: "http_parse_response(raw)", summary: "Parses a raw HTTP response into {status, status_text, proto, headers, body}."},
	BuiltinNameHttpBuildRequest:         {signature: "http_build_request(request)", summary: "Serialises a request hash into HTTP wire bytes."},
	BuiltinNameHttpBuildResponse:        {signature: "http_build_response(response)", summary: "Serialises a response hash into HTTP wire bytes (adds Content-Length)."},
	BuiltinNameHttpConnReadRequest:      {signature: "http_conn_read_request(handle, timeoutMs)", summary: "Reads exactly one HTTP request from a connection handle."},
	BuiltinNameHttpConnReadResponse:     {signature: "http_conn_read_response(handle, timeoutMs)", summary: "Reads exactly one HTTP response from a connection handle."},
	BuiltinNameHttpConnReadRequestHead:  {signature: "http_conn_read_request_head(handle, timeoutMs)", summary: "Reads a request's line+headers without the body (stream it via net_conn_read); adds content_length, chunked."},
	BuiltinNameHttpConnReadResponseHead: {signature: "http_conn_read_response_head(handle, timeoutMs)", summary: "Reads a response's status line+headers without the body (stream it via net_conn_read); adds content_length, chunked."},

	// filesystem parsers — each *_open(image) returns a handle used by the rest.
	BuiltinNameNtfsOpen:      {signature: "ntfs_open(image)", summary: "Opens an NTFS filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to an NTFS image/partition."}}},
	BuiltinNameNtfsListFiles: {signature: "ntfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened NTFS image.", params: []builtinParamDoc{{name: "handle", doc: "Handle from ntfs_open."}, {name: "dir", doc: "Directory path within the image."}}},
	BuiltinNameNtfsReadFile:  {signature: "ntfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened NTFS image.", params: []builtinParamDoc{{name: "handle", doc: "Handle from ntfs_open."}, {name: "path", doc: "File path within the image."}}},
	BuiltinNameNtfsMetadata:  {signature: "ntfs_metadata(handle, path)", summary: "Returns metadata for a file/directory in an opened NTFS image.", params: []builtinParamDoc{{name: "handle", doc: "Handle from ntfs_open."}, {name: "path", doc: "Path within the image."}}},
	BuiltinNameNtfsClose:     {signature: "ntfs_close(handle)", summary: "Closes an NTFS handle and releases its file."},
	BuiltinNameFatOpen:       {signature: "fat_open(image)", summary: "Opens a FAT filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to a FAT image/partition."}}},
	BuiltinNameFatListFiles:  {signature: "fat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened FAT image."},
	BuiltinNameFatReadFile:   {signature: "fat_read_file(handle, path)", summary: "Reads a file's bytes from an opened FAT image."},
	BuiltinNameFatMetadata:   {signature: "fat_metadata(handle, path)", summary: "Returns metadata for a path in an opened FAT image."},
	BuiltinNameFatClose:      {signature: "fat_close(handle)", summary: "Closes a FAT handle and releases its file."},
	BuiltinNameXfatOpen:      {signature: "xfat_open(image)", summary: "Opens an exFAT filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to an exFAT image/partition."}}},
	BuiltinNameXfatListFiles: {signature: "xfat_list_files(handle, dir)", summary: "Lists entries under a directory in an opened exFAT image."},
	BuiltinNameXfatReadFile:  {signature: "xfat_read_file(handle, path)", summary: "Reads a file's bytes from an opened exFAT image."},
	BuiltinNameXfatMetadata:  {signature: "xfat_metadata(handle, path)", summary: "Returns metadata for a path in an opened exFAT image."},
	BuiltinNameXfatClose:     {signature: "xfat_close(handle)", summary: "Closes an exFAT handle and releases its file."},
	BuiltinNameExtOpen:       {signature: "ext_open(image)", summary: "Opens an ext2/3/4 filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to an ext image/partition."}}},
	BuiltinNameExtListFiles:  {signature: "ext_list_files(handle, dir)", summary: "Lists entries under a directory in an opened ext image."},
	BuiltinNameExtReadFile:   {signature: "ext_read_file(handle, path)", summary: "Reads a file's bytes from an opened ext image."},
	BuiltinNameExtMetadata:   {signature: "ext_metadata(handle, path)", summary: "Returns metadata for a path in an opened ext image."},
	BuiltinNameExtClose:      {signature: "ext_close(handle)", summary: "Closes an ext handle and releases its file."},
	BuiltinNameHfsOpen:       {signature: "hfs_open(image)", summary: "Opens an HFS+ filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to an HFS+ image/partition."}}},
	BuiltinNameHfsListFiles:  {signature: "hfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened HFS+ image."},
	BuiltinNameHfsReadFile:   {signature: "hfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened HFS+ image."},
	BuiltinNameHfsMetadata:   {signature: "hfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened HFS+ image."},
	BuiltinNameHfsClose:      {signature: "hfs_close(handle)", summary: "Closes an HFS+ handle and releases its file."},
	BuiltinNameXfsOpen:       {signature: "xfs_open(image)", summary: "Opens an XFS filesystem image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to an XFS image/partition."}}},
	BuiltinNameXfsListFiles:  {signature: "xfs_list_files(handle, dir)", summary: "Lists entries under a directory in an opened XFS image."},
	BuiltinNameXfsReadFile:   {signature: "xfs_read_file(handle, path)", summary: "Reads a file's bytes from an opened XFS image."},
	BuiltinNameXfsMetadata:   {signature: "xfs_metadata(handle, path)", summary: "Returns metadata for a path in an opened XFS image."},
	BuiltinNameXfsClose:      {signature: "xfs_close(handle)", summary: "Closes an XFS handle and releases its file."},

	// disk-image parsers — *_read_at caps length at 32 MiB.
	BuiltinNameVhdiOpen:      {signature: "vhdi_open(image)", summary: "Opens a VHD/VHDX disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to a VHD/VHDX image."}}},
	BuiltinNameVhdiMetadata:  {signature: "vhdi_metadata(handle)", summary: "Returns VHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers)."},
	BuiltinNameVhdiReadAt:    {signature: "vhdi_read_at(handle, offset, length)", summary: "Reads length bytes at a virtual offset from a VHD/VHDX image (length capped at 32 MiB)."},
	BuiltinNameVhdiMapOffset: {signature: "vhdi_map_offset(handle, offset)", summary: "Maps a virtual offset to a backing file offset. Returns {virtual_offset, mapped, file_offset}."},
	BuiltinNameVhdiClose:     {signature: "vhdi_close(handle)", summary: "Closes a VHD/VHDX handle."},
	BuiltinNameEwfOpen:       {signature: "ewf_open(segments)", summary: "Opens an EWF/E01 image (a segment path or an array of segment paths). Returns (result, err).", params: []builtinParamDoc{{name: "segments", doc: "Segment file path or array of paths."}}},
	BuiltinNameEwfMetadata:   {signature: "ewf_metadata(handle)", summary: "Returns EWF metadata (version, sectors/chunks, digests, media info)."},
	BuiltinNameEwfReadAt:     {signature: "ewf_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from an EWF image (length capped at 32 MiB)."},
	BuiltinNameEwfClose:      {signature: "ewf_close(handle)", summary: "Closes an EWF handle and its segment files."},
	BuiltinNameRawOpen:       {signature: "raw_open(image)", summary: "Opens a raw disk image and returns a handle. Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to a raw (dd) image."}}},
	BuiltinNameRawMetadata:   {signature: "raw_metadata(handle)", summary: "Returns {file_size, assumed_sector_size, sector_size_assumed} (raw images carry no real sector-size metadata)."},
	BuiltinNameRawReadAt:     {signature: "raw_read_at(handle, offset, length)", summary: "Reads length bytes at an offset from a raw image (length capped at 32 MiB)."},
	BuiltinNameRawClose:      {signature: "raw_close(handle)", summary: "Closes a raw image handle."},

	// partition table parser
	BuiltinNameTableOpen:           {signature: "table_open(image)", summary: "Opens a disk image and parses its partition table(s) (MBR/GPT). Returns (result, err).", params: []builtinParamDoc{{name: "image", doc: "Path to a disk image."}}},
	BuiltinNameTableListPartitions: {signature: "table_list_partitions(handle)", summary: "Lists partitions with LBA ranges, type, name, flags, and hex type_code/attributes."},
	BuiltinNameTablePartitionInfo:  {signature: "table_partition_info(handle, index)", summary: "Returns details for a single partition by index."},
	BuiltinNameTableClose:          {signature: "table_close(handle)", summary: "Closes a partition-table handle."},

	// close helpers that lacked docs
	BuiltinNameCacheClose: {signature: "cache_close(name)", summary: "Closes a named cache and frees its entries and backend."},
	BuiltinNameRegClose:   {signature: "reg_close(handle)", summary: "Closes a registry-hive handle opened with reg_open."},
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
	{prefix: "str_", summary: "String manipulation helper (case, trim, pad, join, slice, format)."},
	{prefix: "hash_", summary: "Cryptographic/checksum hashing helper (md5/sha1/sha256/sha512/crc32/blake2)."},
	{prefix: "math_", summary: "Mathematical constant accessor."},
	{prefix: "rand", summary: "Random value generator."},
	{prefix: "uuid_", summary: "UUID generator."},
	{prefix: "time_", summary: "Time and date helper (Unix timestamps, formatting, parsing)."},
	{prefix: "base64", summary: "Base64 encoding/decoding helper."},
	{prefix: "base32", summary: "Base32 encoding/decoding helper."},
	{prefix: "go_", summary: "Go-compiled binary analysis helper (GoReSym): build info, build ID, and symbol recovery from stripped binaries."},
	{prefix: "ip_", summary: "IP address helper (validation, CIDR membership, conversions)."},
	{prefix: "timeline_", summary: "Forensic timeline helper (sort/merge events into a supertimeline)."},
	{prefix: "hashset_", summary: "Known-file hash-set helper (NSRL-style load/lookup for filtering)."},
	{prefix: "hive_", summary: "Real Windows registry hive parser (regf binary format)."},
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
