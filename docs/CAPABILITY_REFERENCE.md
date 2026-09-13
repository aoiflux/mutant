# Mutant Capability Reference

> Generated from the builtin metadata (`builtin/metadata.go`) — the source of truth.
> Regenerate with `go run ./cmd/gendocs`; check for drift with `go run ./cmd/gendocs -check`.
> Do not hand-edit the tables below: signatures, parameter types, platforms, and
> counts are all read from the metadata, and edits here are overwritten.

This is the canonical, category-grouped catalog of every Mutant builtin. There are currently **482 registered builtins** across **37 capability categories**. For language syntax and keywords see [MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md); deep-dive guides are linked per category below.

## How to read this reference

- **Fallible builtins return a `(value, err)` pair**, matching the language idiom `let value, err = some_call(...);`. Check `err` before using `value`. Infallible helpers return a bare value.
- **Parameter types are shown inline** in each signature, e.g. `str_repeat(s: STRING, n: INTEGER)`. A parameter with no type shown accepts any value. These are the same contracts the language server checks a call against (the `builtinArgType` diagnostic), and the same words the runtime uses when a call fails. A parameter shown as `BYTES|STRING` accepts either representation and the builtin hands back the one it was given; `string_to_bytes(s, "raw")` converts losslessly from a builtin that still returns text.
- **The Platforms column** lists the operating systems a builtin actually works on. `all` means it is pure-Go and cross-platform (it operates on captured artifacts, so it runs on any host). A restricted set (e.g. `windows/linux`) means the builtin fails honestly elsewhere — and the language server will flag such a call when you are editing on an unsupported OS (the `platformSupport` diagnostic).
- **Pure-Go, no cgo.** The entire standard library builds and runs with `CGO_ENABLED=0` on Windows, Linux, and macOS.

## Platform-restricted builtins

Almost every builtin is cross-platform. The exceptions:

| Builtin | Platforms | Note |
| --- | --- | --- |
| `process_memory_scan` | windows, linux | fails honestly on other platforms |
| `process_modules` | windows, linux | fails honestly on other platforms |

`process_kill` and `reg_open` work on all platforms but have platform-specific behavior in one path; hover in the editor shows the note.

---

## Standard Library (59)

Core language primitives: collection and hash operations, first-class higher-order functions (`map`/`filter`/`reduce`/`each`/`sort_by`), math helpers, I/O, and runtime/security introspection.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `abs(x: INTEGER\|FLOAT) -> INTEGER\|FLOAT` | all | Absolute value (preserves INTEGER/FLOAT type). |
| `avg(array: ARRAY) -> FLOAT` | all | Arithmetic mean of a numeric array (FLOAT); errors on empty. |
| `ceil(x: INTEGER\|FLOAT) -> INTEGER` | all | Smallest integer >= x (INTEGER). |
| `clamp(x: INTEGER\|FLOAT, lo: INTEGER\|FLOAT, hi: INTEGER\|FLOAT) -> INTEGER\|FLOAT` | all | Constrains x to the range [lo, hi]. |
| `concat(a: ARRAY, b: ARRAY) -> ARRAY` | all | Returns a new array with the elements of a followed by b. |
| `contains(array: ARRAY, value) -> BOOLEAN` | all | Returns whether array contains value (by value equality). |
| `debug_status() -> (HASH, ERROR)` | all | Returns runtime/debugger status information. |
| `delete(hash: HASH, key: STRING\|INTEGER\|FLOAT\|BOOLEAN) -> HASH` | all | Returns a new hash with key removed. |
| `each(array: ARRAY, fn: FUNCTION) -> NULL` | all | Calls fn for each element for its side effects and returns null. fn takes (element) or (element, index). |
| `entries(hash: HASH) -> ARRAY` | all | Returns the hash as an array of [key, value] pairs (sorted by key). |
| `error(message: STRING, context?: STRING, related?: HASH) -> ERROR` | all | Constructs an error value carrying a message, an origin, and any related facts. Single-return: it cannot fail. |
| `filter(array: ARRAY, fn: FUNCTION) -> ARRAY` | all | Returns a new array of the elements for which fn is truthy. fn takes (element) or (element, index). |
| `first(array: ARRAY) -> ANY` | all | Returns the first element of an array. |
| `flatten(array: ARRAY) -> ARRAY` | all | Flattens one level of nested arrays. |
| `floor(x: INTEGER\|FLOAT) -> INTEGER` | all | Largest integer <= x (INTEGER). |
| `get(hash: HASH, key: STRING\|INTEGER\|FLOAT\|BOOLEAN, default) -> ANY` | all | Returns hash[key], or default when the key is absent. |
| `gets() -> STRING` | all | Reads a full line of input from stdin and returns it as a STRING (newline trimmed). Use to_int/to_float/parse_int to convert. |
| `has_key(hash: HASH, key: STRING\|INTEGER\|FLOAT\|BOOLEAN) -> BOOLEAN` | all | Returns whether hash contains key. |
| `help(topic?: STRING, mode?: STRING) -> STRING` | all | Returns help text: an overview, a topic (keywords/builtins/examples/docs), or details for a specific builtin name. |
| `index_of(array: ARRAY, value) -> INTEGER` | all | Returns the first index of value in array, or -1. |
| `int_to_ip(n: INTEGER) -> STRING` | all | Converts a 32-bit integer to an IPv4 dotted-quad string. |
| `is_null(v) -> BOOLEAN` | all | Returns whether v is NULL. |
| `keys(hash: HASH) -> ARRAY` | all | Returns the hash keys as an array (sorted for determinism). |
| `last(array: ARRAY) -> ANY` | all | Returns the last element of an array. |
| `len(value: STRING\|BYTES\|ARRAY\|HASH) -> INTEGER` | all | Returns the length of a string, buffer, array, or hash. |
| `map(array: ARRAY, fn: FUNCTION) -> ARRAY` | all | Returns a new array of fn applied to each element. fn takes (element) or (element, index). |
| `max(value: INTEGER\|FLOAT, ...values: INTEGER\|FLOAT) -> INTEGER\|FLOAT` | all | Returns the largest of the numeric arguments (original type preserved). |
| `merge(a: HASH, b: HASH) -> HASH` | all | Returns a new hash combining a and b (b wins on key conflicts). |
| `min(value: INTEGER\|FLOAT, ...values: INTEGER\|FLOAT) -> INTEGER\|FLOAT` | all | Returns the smallest of the numeric arguments (original type preserved). |
| `mod(a: INTEGER\|FLOAT, b: INTEGER\|FLOAT) -> INTEGER\|FLOAT` | all | Returns a modulo b; errors on b=0. Integer mod when both are INTEGER. |
| `peach(array: ARRAY, fn: FUNCTION, workers?: INTEGER) -> NULL` | all | Like each, but calls fn on elements concurrently for their side effects and returns null. fn takes (element) or (element, index). Each worker runs on its own VM with a snapshot of globals, so fn should report through a shared store (cache_*/db_*) rather than by assigning to a global. |
| `pmap(array: ARRAY, fn: FUNCTION, workers?: INTEGER) -> ARRAY` | all | Like map, but applies fn to elements concurrently and returns results in the original order. fn takes (element) or (element, index). Each worker runs on its own VM with a snapshot of globals, so fn should be self-contained: it cannot write back to a global. |
| `pop(array: ARRAY) -> ARRAY` | all | Returns a new array without the last element. |
| `pow(x: INTEGER\|FLOAT, y: INTEGER\|FLOAT) -> FLOAT` | all | Returns x raised to the power y (FLOAT). |
| `push(array: ARRAY, value) -> ARRAY` | all | Returns a new array with value appended. |
| `putf(format, ...values) -> NULL` | all | Formats and prints values using a format string. |
| `putln(...values) -> NULL` | all | Prints values separated by spaces, followed by a newline. |
| `range(start: INTEGER, end: INTEGER, step?: INTEGER) -> []INTEGER` | all | Returns an array of integers from start (inclusive) to end (exclusive); step defaults to 1. |
| `reduce(array: ARRAY, fn: FUNCTION, initial) -> ANY` | all | Folds the array to a single value: fn(accumulator, element) starting from initial. |
| `rest(array: ARRAY) -> ARRAY` | all | Returns a new array without the first element. |
| `reverse(array: ARRAY) -> ARRAY` | all | Returns a reversed copy of an array. |
| `round(x: INTEGER\|FLOAT) -> INTEGER` | all | Nearest integer to x (INTEGER). |
| `sandbox_status() -> (HASH, ERROR)` | all | Returns sandbox-detection status information. |
| `security_diagnostics() -> (HASH, ERROR)` | all | Returns security diagnostics for the current runtime. |
| `serve_arg() -> (ANY, ERROR)` | all | Inside a net_serve handler, returns the shared arg passed to net_serve; null otherwise. |
| `serve_conn() -> (INTEGER\|NULL, ERROR)` | all | Inside a net_serve handler, returns the connection handle (INTEGER); null otherwise. |
| `set(hash: HASH, key: STRING\|INTEGER\|FLOAT\|BOOLEAN, value) -> HASH` | all | Returns a new hash with key set to value (original unchanged). |
| `sleep_ms(ms: INTEGER) -> (BOOLEAN, ERROR)` | all | Blocks the current handler for ms milliseconds. |
| `slice(array: ARRAY, start: INTEGER, end: INTEGER) -> ARRAY` | all | Returns the sub-array array[start:end] (bounds-clamped). |
| `sort(array: ARRAY) -> ARRAY` | all | Returns a sorted copy of an array (all numbers or all strings). |
| `sort_by(array: ARRAY, fn: FUNCTION) -> ARRAY` | all | Returns a new array stably sorted by the key fn returns for each element (INTEGER/FLOAT/STRING keys). |
| `sqrt(x: INTEGER\|FLOAT) -> FLOAT` | all | Returns the square root of x (FLOAT); errors on negative x. |
| `string_to_bytes(s: STRING, encoding: STRING) -> (BYTES, ERROR)` | all | Converts text to a BYTES buffer under a named encoding: "raw", "utf8" (validated), "latin1", "hex" or "base64". Returns (bytes, err). |
| `sum(array: ARRAY) -> INTEGER\|FLOAT` | all | Sum of a numeric array (INTEGER if all elements are integers). |
| `type_of(v) -> STRING` | all | Returns the object type name of v (e.g. INTEGER, STRING, ARRAY). |
| `unique(array: ARRAY) -> ARRAY` | all | Returns a new array with duplicate values removed (order preserved). |
| `values(hash: HASH) -> ARRAY` | all | Returns the hash values as an array (ordered by sorted key). |
| `with_resource(resource, closer: STRING\|FUNCTION, fn: FUNCTION) -> (ANY, ERROR)` | all | Calls fn with a resource an open call returned and always closes it afterwards -- whether fn returns a value, returns an error, or fails outright. closer is the name of a closing builtin ("ntfs_close") or a function taking the resource. If the open itself failed, fn never runs and the open's error comes back unchanged, so wrapping an existing call in with_resource does not change what the program sees. Returns (value, err): value is what fn returned, and err is the first failure among the open, an error fn returned, and the close. When fn and the close both fail, fn's error is the one returned and the close's is attached to it as related["close_error"]. |
| `zip(a: ARRAY, b: ARRAY) -> ARRAY` | all | Returns an array of [a[i], b[i]] pairs up to the shorter length. |

## Testing (10)

What `mutant test` reads. `test(name, fn)` names a test and runs it where it is written, so a test file reads top to bottom and a test declared inside another is a subtest of it; `before_each`/`after_each` register fixtures for the tests declared after them. The assertions record what they saw against the test that is running AND return it, so a failure is both something the report can name with a file and line and an ordinary value the program can look at. A test that dies is caught at its own boundary and costs the file no other test. See [TESTING.md](TESTING.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `after_each(fn: FUNCTION) -> NULL` | all | Registers fn to run after each test declared after this call, at this nesting level and inside it. It runs whether the test passed, failed, or ended in an error. |
| `assert(condition, message?: STRING) -> BOOLEAN` | all | Fails the current test unless condition is truthy. |
| `assert_contains(container: STRING\|ARRAY\|HASH, value, message?: STRING) -> BOOLEAN` | all | Fails the current test unless container holds value: a substring of a string, an element of an array, or a key of a hash. |
| `assert_eq(got, want, message?: STRING) -> BOOLEAN` | all | Fails the current test unless got equals want. Scalars compare by value; arrays, hashes and structs compare by their rendered form, so key order does not matter. |
| `assert_err(value, substring?: STRING) -> BOOLEAN` | all | Fails the current test unless value is an error, optionally requiring its message to contain substring. This is what the second binding of a (value, err) call is checked with. |
| `assert_ne(got, unwanted, message?: STRING) -> BOOLEAN` | all | Fails the current test when got equals unwanted, compared the way assert_eq compares. |
| `assert_ok(value, message?: STRING) -> BOOLEAN` | all | Fails the current test when value is an error, quoting the error's own message. This is the check to put on the second binding of a (value, err) call that is expected to succeed. |
| `before_each(fn: FUNCTION) -> NULL` | all | Registers fn to run before each test declared after this call, at this nesting level and inside it. A failure in fn fails the test it was preparing. |
| `fail(message: STRING) -> ERROR` | all | Fails the current test unconditionally with the given message. For the branch a test should never reach. |
| `test(name: STRING, fn: FUNCTION) -> BOOLEAN` | all | Runs fn as a named test and records whether it passed. Tests run where they are written, in order; a test declared inside another is a subtest of it. A runtime error inside fn fails that test and the file keeps going. |

## Concurrency (8)

Run work alongside the rest of the program and pass values between the pieces. `spawn` starts a closure on its own VM and hands back a handle for `task_wait`/`task_done`; `chan_*` moves values between them. Each task gets a snapshot of globals, so a channel or a return value is the way back, not a shared variable. For applying one callback across an array, reach for `pmap`/`peach` in the standard library instead.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `chan_close(handle: INTEGER) -> (BOOLEAN, ERROR)` | all | Closes a channel, waking every waiting sender and receiver. Returns true when this call did the closing and false when the channel was already closed. Receivers can still drain values that were already queued; the handle is reclaimed once enough other channels have been closed after it, after which it reports as unknown. |
| `chan_new(capacity?: INTEGER) -> (INTEGER, ERROR)` | all | Creates a channel for passing values between concurrently running code and returns its handle. Capacity 0 (the default) is unbuffered, so a send waits for a receive; a positive capacity lets that many values queue first. At most 1024 channels may be open at once; close each one with chan_close when you are done with it. |
| `chan_recv(handle: INTEGER, timeoutMs?: INTEGER) -> (HASH, ERROR)` | all | Takes the next value off a channel, waiting for one if the channel is empty. Returns {ok, value, closed, timeout}; check ok before reading value, since null is itself a sendable value. Values already queued are delivered even after the channel is closed. |
| `chan_send(handle: INTEGER, value, timeoutMs?: INTEGER) -> (BOOLEAN, ERROR)` | all | Puts a value on a channel, waiting for a receiver if the channel is full. Returns true once the value is handed over and false if the timeout ran out first; sending on a closed channel is an error. |
| `chan_try_recv(handle: INTEGER) -> (HASH, ERROR)` | all | Takes a value off a channel only if one is already waiting, and never blocks. Returns the same {ok, value, closed, timeout} shape as chan_recv. |
| `spawn(fn: FUNCTION, arg?) -> (INTEGER, ERROR)` | all | Runs fn on its own VM alongside the rest of the program and returns a task handle to collect it with. fn takes no arguments, or one if arg is given. The task sees a snapshot of globals taken at the spawn, so it should report back through its return value or a channel rather than by assigning to a global. |
| `task_done(handle: INTEGER) -> (BOOLEAN, ERROR)` | all | Reports whether a spawned task has finished, without waiting for it. |
| `task_wait(handle: INTEGER, timeoutMs?: INTEGER) -> (ANY, ERROR)` | all | Waits for a spawned task and returns the value its function returned. Whatever stopped the task arrives in the error slot. Without a timeout it waits indefinitely; running out of time is reported as an error and leaves the task collectable. Collecting a task releases its handle, so wait for it once. |

## Strings (18)

Rune-aware string manipulation: case, trimming, padding, slicing, joining, and formatting. Pairs with the `text_*`/`regex_*` matching family.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `str_char_at(s: STRING, index: INTEGER) -> STRING` | all | Returns the rune at index as a string. |
| `str_ends_with(s: STRING, suffix: STRING) -> BOOLEAN` | all | Returns whether s ends with suffix. |
| `str_format(format: STRING, ...values) -> STRING` | all | Returns a printf-style formatted string (like putf but returns instead of printing). |
| `str_join(array: ARRAY, sep: STRING) -> STRING` | all | Joins an array of strings with sep (inverse of text_split). |
| `str_lower(s: STRING) -> STRING` | all | Returns s with all letters lower-cased. |
| `str_pad_left(s: STRING, width: INTEGER, pad: STRING) -> STRING` | all | Left-pads s with pad until it reaches width runes. |
| `str_pad_right(s: STRING, width: INTEGER, pad: STRING) -> STRING` | all | Right-pads s with pad until it reaches width runes. |
| `str_repeat(s: STRING, n: INTEGER) -> STRING` | all | Returns s repeated n times. |
| `str_reverse(s: STRING) -> STRING` | all | Returns s reversed (rune-aware). |
| `str_starts_with(s: STRING, prefix: STRING) -> BOOLEAN` | all | Returns whether s begins with prefix. |
| `str_substr(s: STRING, start: INTEGER, length: INTEGER) -> STRING` | all | Returns length runes of s starting at rune index start (clamped to bounds). |
| `str_title(s: STRING) -> STRING` | all | Upper-cases the first letter of each word in s. |
| `str_trim(s: STRING) -> STRING` | all | Returns s with leading and trailing whitespace removed. |
| `str_trim_left(s: STRING, cutset: STRING) -> STRING` | all | Trims any leading characters in cutset from s. |
| `str_trim_prefix(s: STRING, prefix: STRING) -> STRING` | all | Removes prefix from s if present. |
| `str_trim_right(s: STRING, cutset: STRING) -> STRING` | all | Trims any trailing characters in cutset from s. |
| `str_trim_suffix(s: STRING, suffix: STRING) -> STRING` | all | Removes suffix from s if present. |
| `str_upper(s: STRING) -> STRING` | all | Returns s with all letters upper-cased. |

## Text Analysis (14)

Substring search, splitting/replacing, regular expressions, and fuzzy matching (Levenshtein, Jaro-Winkler, similarity).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `regex_capture_groups(pattern: STRING, input: STRING) -> ([]STRING, ERROR)` | all | Returns full regex capture array (full match plus groups). |
| `regex_find(pattern: STRING, input: STRING) -> (STRING\|NULL, ERROR)` | all | Finds the first regex match in input. |
| `regex_find_all(pattern: STRING, input: STRING, limit?: INTEGER) -> ([]STRING, ERROR)` | all | Finds all regex matches with optional result limit. |
| `regex_match(pattern: STRING, input: STRING) -> (BOOLEAN, ERROR)` | all | Returns whether regex pattern matches input. |
| `regex_replace(pattern: STRING, input: STRING, replacement: STRING) -> (STRING, ERROR)` | all | Replaces all regex matches in input with replacement text. |
| `text_contains(haystack: STRING, needle: STRING) -> BOOLEAN` | all | Returns whether a string contains a substring. |
| `text_count(haystack: STRING, needle: STRING) -> INTEGER` | all | Counts non-overlapping substring occurrences. |
| `text_fuzzy_find(query: STRING, candidates: ARRAY, maxDistance?: INTEGER) -> HASH` | all | Finds the closest fuzzy match in an array of candidate strings. |
| `text_index(haystack: STRING, needle: STRING) -> INTEGER` | all | Returns the first index of substring occurrence, or -1. |
| `text_jaro_winkler(left: STRING, right: STRING) -> FLOAT` | all | Computes Jaro-Winkler string similarity score. |
| `text_levenshtein(left: STRING, right: STRING) -> INTEGER` | all | Computes Levenshtein edit distance between two strings. |
| `text_replace(text: STRING, old: STRING, new: STRING, count?: INTEGER) -> STRING` | all | Replaces substring occurrences in text; count limits how many (all by default). |
| `text_similarity(left: STRING, right: STRING) -> FLOAT` | all | Computes normalized Levenshtein similarity between two strings. |
| `text_split(text: STRING, sep: STRING) -> []STRING` | all | Splits text by separator and returns an array of parts. |

## Structured Data (46)

The formats evidence actually arrives in. JSON and NDJSON/JSONL (Zeek, Elastic bulk, OCSF), CSV/TSV (every SIEM export and hash set), XML (Scheduled Tasks, OOXML, Nessus, plist), YAML including multi-document streams (Sigma rulesets), TOML, and the binary serializations -- CBOR for COSE/WebAuthn, MessagePack for agent traffic, plus schemaless walkers for protobuf and DER/ASN.1 that report structure when no `.proto` or ASN.1 module is at hand. Then base64/base32/hex/URL encoding, gzip/zlib compression, base conversion, and type conversion. Every decoder shares one bridge, so a byte string is a BYTES buffer and a timestamp is RFC 3339 no matter which format it came from. See [STRUCTURED_DATA.md](STRUCTURED_DATA.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `base32_decode(s: STRING) -> (STRING, ERROR)` | all | Decodes standard base32; returns (bytes, err). |
| `base32_encode(s: STRING\|BYTES) -> STRING` | all | Standard base32-encodes s. |
| `base64_decode(s: STRING) -> (STRING, ERROR)` | all | Decodes standard base64; returns (bytes, err). |
| `base64_decode_bytes(s: STRING) -> (BYTES, ERROR)` | all | Decodes standard base64 into a BYTES buffer; returns (bytes, err). |
| `base64_encode(s: STRING\|BYTES) -> STRING` | all | Standard base64-encodes s. |
| `base64url_decode(s: STRING) -> (STRING, ERROR)` | all | Decodes URL-safe base64; returns (bytes, err). |
| `base64url_encode(s: STRING\|BYTES) -> STRING` | all | URL-safe base64-encodes s. |
| `cbor_encode(value: STRING\|BYTES\|INTEGER\|FLOAT\|BOOLEAN\|NULL\|ARRAY\|HASH\|STRUCT) -> (BYTES, ERROR)` | all | Serializes a Mutant value as canonical CBOR: map keys are sorted and integers use their shortest form, so hash_sha256(cbor_encode(v)) is a stable identifier for v. A buffer encodes as a CBOR byte string. |
| `cbor_parse(data: BYTES\|STRING) -> (ANY, ERROR)` | all | Parses CBOR -- COSE, WebAuthn, IoT telemetry. Byte strings decode to buffers, not text; tagged items are preserved as {_cbor_tag, value} rather than dropped; integer map keys are supported (COSE labels them that way); duplicate keys are refused. Nesting is capped at 64 levels. |
| `csv_parse(data: BYTES\|STRING, options?: HASH) -> (ARRAY, ERROR)` | all | Parses CSV/TSV into an array of hashes keyed by the header row. options: delimiter (default ","), comment, header (default true), trim_space, lazy_quotes. A UTF-8 BOM is stripped, duplicate column names are refused rather than silently resolved, and fields beyond the header land in an _extra array. With header:false each row is an array of strings instead. |
| `csv_stringify(rows: ARRAY, options?: HASH) -> (STRING, ERROR)` | all | Serializes an array of hashes (or arrays) as CSV/TSV. options: delimiter, header (default true), columns (explicit column order), crlf. Without an explicit columns list the header is the sorted union of every row's keys, so a row missing a key writes an empty field rather than shifting the others. |
| `der_parse(data: BYTES\|STRING) -> ([]HASH, ERROR)` | all | Walks DER/ASN.1 structurally, without a schema -- what x509_parse and pem_decode already need internally, and what a certificate extension or a Kerberos ticket needs when no ASN.1 module is at hand. Each node reports {offset, header_len, length, class, tag, constructed, tag_name}, constructed nodes carry children, and primitives carry raw value bytes plus a decoded rendering for universal types (OIDs dotted, big INTEGERs as decimal text rather than truncated, times as RFC 3339). BER indefinite length is refused by name. |
| `from_base(s: STRING, base: INTEGER) -> (INTEGER, ERROR)` | all | Parses s as an integer in the given base (2–36); returns (int, err). |
| `gunzip(s: STRING\|BYTES, max_bytes?: INTEGER) -> (STRING, ERROR)` | all | Gzip-decompresses s; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise. |
| `gunzip_bytes(s: STRING\|BYTES, max_bytes?: INTEGER) -> (BYTES, ERROR)` | all | Gzip-decompresses s into a BYTES buffer; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise. |
| `gzip(s: STRING\|BYTES) -> STRING` | all | Gzip-compresses s (returns a byte string). |
| `hex_decode(s: STRING) -> (STRING, ERROR)` | all | Decodes a hex string to bytes; returns (bytes, err). |
| `hex_decode_bytes(s: STRING) -> (BYTES, ERROR)` | all | Decodes a hex string into a BYTES buffer; returns (bytes, err). |
| `hex_encode(s: STRING\|BYTES) -> STRING` | all | Hex-encodes a byte string to lowercase hex. |
| `json_parse(text: STRING) -> (ANY, ERROR)` | all | Parses JSON text into Mutant values. |
| `json_stringify(value: STRING\|BYTES\|INTEGER\|FLOAT\|BOOLEAN\|NULL\|ARRAY\|HASH) -> (STRING, ERROR)` | all | Serializes Mutant values into JSON text. |
| `msgpack_encode(value: STRING\|BYTES\|INTEGER\|FLOAT\|BOOLEAN\|NULL\|ARRAY\|HASH\|STRUCT) -> (BYTES, ERROR)` | all | Serializes a Mutant value as MessagePack with sorted map keys and compact integers, so the output is deterministic for a given value. |
| `msgpack_parse(data: BYTES\|STRING) -> (ANY, ERROR)` | all | Parses MessagePack -- agent check-ins, queue payloads, Fluentd forward traffic. Binary values decode to buffers, not text. Input carrying more than one value is reported rather than ignored: a blob that decodes and keeps going is either a stream or not what it was thought to be. |
| `ndjson_parse(data: BYTES\|STRING) -> ([]ANY, ERROR)` | all | Parses newline-delimited JSON (NDJSON/JSONL) -- the wire format of Zeek, Elastic bulk and OCSF streams. Blank lines are skipped; a malformed line fails with its line number rather than silently truncating the stream. |
| `ndjson_stringify(values: ARRAY) -> (STRING, ERROR)` | all | Serializes an array as newline-delimited JSON, one value per line, with a trailing newline so the output concatenates with another stream. |
| `parse_float(s: STRING) -> (FLOAT, ERROR)` | all | Parses s as a float; returns (float, err). |
| `parse_int(s: STRING, base: INTEGER) -> (INTEGER, ERROR)` | all | Parses s as an integer in base (0 auto-detects); returns (int, err). |
| `plist_parse(path: STRING) -> (ANY, ERROR)` | all | Parses an Apple property list (binary bplist00 or XML) into a Mutant value: dict->hash, array->array, string/integer/real/bool as scalars; dates and data become strings. Returns (value, err). |
| `protobuf_parse(data: BYTES\|STRING) -> ([]HASH, ERROR)` | all | Walks protobuf wire format without a .proto -- the situation an analyst holding a gRPC capture is actually in. Each field reports {field, wire_type, offset} plus every reading its bytes admit: a varint as itself, as zigzag and as bool; a length-delimited field as bytes, plus text and message when those parse. Naming the ambiguity is the honest thing a schemaless reader can do. |
| `to_base(n: INTEGER, base: INTEGER) -> STRING` | all | Formats integer n in the given base (2–36). |
| `to_bool(v: BOOLEAN\|INTEGER\|FLOAT\|STRING) -> (BOOLEAN, ERROR)` | all | Converts a bool/number/string to BOOLEAN; returns (bool, err). |
| `to_float(v: INTEGER\|FLOAT\|BOOLEAN\|STRING) -> (FLOAT, ERROR)` | all | Converts a number/bool/string to FLOAT; returns (float, err). |
| `to_int(v: INTEGER\|FLOAT\|BOOLEAN\|STRING) -> (INTEGER, ERROR)` | all | Converts a number/bool/string to INTEGER; returns (int, err). |
| `to_string(v) -> STRING` | all | Converts any value to its STRING representation. |
| `toml_parse(data: BYTES\|STRING) -> (HASH, ERROR)` | all | Parses TOML into a hash. TOML datetimes become RFC 3339 strings, so they sort against every other timestamp the language produces. |
| `toml_stringify(value: HASH\|STRUCT) -> (STRING, ERROR)` | all | Serializes a hash or struct as TOML. The top level must be a table -- TOML has no other document shape -- and a buffer is written as hex, matching yaml_stringify. |
| `url_decode(s: STRING) -> (STRING, ERROR)` | all | URL query-unescapes s; returns (value, err). |
| `url_encode(s: STRING) -> STRING` | all | URL query-escapes s. |
| `xml_find(node: HASH, selector: STRING) -> ([]HASH, ERROR)` | all | Selects descendants of a parsed element by a slash-separated path. Three rules, not XPath: a name matches an element, * matches any single level, ** matches any number of levels including none (so "**/Task" also finds a direct child). |
| `xml_parse(data: BYTES\|STRING) -> (HASH, ERROR)` | all | Parses XML into a node tree: {name, namespace, attrs, text, children}. Comments, processing instructions and directives are skipped, undeclared entities fail rather than expand (closing billion-laughs and XXE), and windows-1252/iso-8859-1/-15/windows-1251 documents are decoded by their declared charset -- an unrecognised charset fails by name rather than being misdecoded. |
| `yaml_parse(data: BYTES\|STRING) -> (ANY, ERROR)` | all | Parses the first YAML document -- Sigma rules, CI config, cloud manifests. A file of ----separated documents needs yaml_parse_all, which is why this one exists as a pair. |
| `yaml_parse_all(data: BYTES\|STRING) -> ([]ANY, ERROR)` | all | Parses every document in a multi-document YAML stream. A Sigma ruleset is one file of ----separated documents, and yaml_parse would return only the first, silently. |
| `yaml_stringify(value: STRING\|BYTES\|INTEGER\|FLOAT\|BOOLEAN\|NULL\|ARRAY\|HASH\|STRUCT) -> (STRING, ERROR)` | all | Serializes a Mutant value as YAML. A buffer is written as hex, matching Inspect and json_stringify; string_to_bytes(s, "hex") converts it back. |
| `zlib_compress(s: STRING\|BYTES) -> STRING` | all | Zlib-compresses s (returns a byte string). |
| `zlib_decompress(s: STRING\|BYTES, max_bytes?: INTEGER) -> (STRING, ERROR)` | all | Zlib-decompresses s; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise. |
| `zlib_decompress_bytes(s: STRING\|BYTES, max_bytes?: INTEGER) -> (BYTES, ERROR)` | all | Zlib-decompresses s into a BYTES buffer; returns (bytes, err). Refuses to produce more than 1000x its input, capped at 1 GiB, unless max_bytes says otherwise. |

## Math (5)

Numeric constants and random-number helpers (cryptographically-random bytes via `rand_bytes`). Arithmetic helpers like `abs`/`min`/`max`/`sum` live in the standard library.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `math_e() -> FLOAT` | all | Returns the constant e. |
| `math_pi() -> FLOAT` | all | Returns the constant pi. |
| `rand() -> FLOAT` | all | Returns a random FLOAT in [0, 1). |
| `rand_bytes(n: INTEGER) -> STRING` | all | Returns n cryptographically-random bytes (as a byte string). |
| `rand_int(lo: INTEGER, hi: INTEGER) -> INTEGER` | all | Returns a random INTEGER in [lo, hi). |

## Hashing (11)

Cryptographic and checksum digests (MD5/SHA-1/SHA-256/SHA-512/CRC-32/BLAKE2), HMAC, and identifier generators (UUID v4/v7, nanoid, random hex).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `hash_blake2(s: STRING\|BYTES) -> STRING` | all | Returns the lowercase hex BLAKE2b-256 digest of s. |
| `hash_crc32(s: STRING\|BYTES) -> STRING` | all | Returns the CRC-32 (IEEE) checksum of s as 8 hex chars. |
| `hash_md5(s: STRING\|BYTES) -> STRING` | all | Returns the lowercase hex MD5 digest of s. |
| `hash_sha1(s: STRING\|BYTES) -> STRING` | all | Returns the lowercase hex SHA-1 digest of s. |
| `hash_sha256(s: STRING\|BYTES) -> STRING` | all | Returns the lowercase hex SHA-256 digest of s. |
| `hash_sha512(s: STRING\|BYTES) -> STRING` | all | Returns the lowercase hex SHA-512 digest of s. |
| `hmac(key: STRING\|BYTES, message: STRING\|BYTES, algo: STRING) -> STRING` | all | Returns the hex HMAC of message under key. algo is md5/sha1/sha256/sha512. |
| `nanoid(n: INTEGER) -> STRING` | all | Returns a URL-safe random identifier of length n. |
| `random_hex(n: INTEGER) -> STRING` | all | Returns n cryptographically-random bytes as a 2n-char hex string. |
| `uuid_v4() -> STRING` | all | Returns a random (v4) UUID string. |
| `uuid_v7() -> STRING` | all | Returns a time-ordered (v7) UUID string. |

## Time (7)

Unix timestamps, formatting, parsing, and arithmetic (UTC).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `time_add(unix: INTEGER, seconds: INTEGER) -> INTEGER` | all | Returns the Unix timestamp shifted by seconds. |
| `time_diff(a: INTEGER, b: INTEGER) -> INTEGER` | all | Returns a - b in seconds (both Unix timestamps). |
| `time_format(unix: INTEGER, layout: STRING) -> STRING` | all | Formats a Unix timestamp (UTC) using a Go reference layout. |
| `time_ms() -> (INTEGER, ERROR)` | all | Returns the current Unix time in milliseconds. |
| `time_now() -> HASH` | all | Returns the current UTC time as a hash {unix, iso, year, month, day, hour, minute, second}. |
| `time_parse(value: STRING, layout: STRING) -> (INTEGER, ERROR)` | all | Parses value with a Go reference layout; returns (unixSeconds, err). |
| `time_unix() -> INTEGER` | all | Returns the current Unix time in seconds. |

## Bytes (31)

Binary buffer inspection and construction: fixed-width integer reads/writes (LE/BE), a streaming cursor, slicing, and byte/char conversions.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bytes_char_from_int(value: INTEGER) -> (STRING, ERROR)` | all | Converts an integer byte value to a single-character string. |
| `bytes_cstr_at(data: STRING\|BYTES, offset: INTEGER, maxLength: INTEGER) -> (STRING, ERROR)` | all | Reads null-terminated string from bytes at offset. |
| `bytes_cursor_eof(cursor: HASH) -> (BOOLEAN, ERROR)` | all | Returns whether cursor is at end-of-buffer. |
| `bytes_cursor_new(data: STRING\|BYTES) -> (HASH, ERROR)` | all | Creates a cursor for structured byte parsing. |
| `bytes_cursor_read_u16_be(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 16-bit big-endian integer from cursor. |
| `bytes_cursor_read_u16_le(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 16-bit little-endian integer from cursor. |
| `bytes_cursor_read_u32_be(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 32-bit big-endian integer from cursor. |
| `bytes_cursor_read_u32_le(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 32-bit little-endian integer from cursor. |
| `bytes_cursor_read_u64_be(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 64-bit big-endian integer from cursor. |
| `bytes_cursor_read_u64_le(cursor: HASH) -> (HASH, ERROR)` | all | Reads unsigned 64-bit little-endian integer from cursor. |
| `bytes_cursor_read_u8(cursor: HASH) -> (HASH, ERROR)` | all | Reads one unsigned byte from cursor. |
| `bytes_cursor_seek(cursor: HASH, offset: INTEGER) -> (HASH, ERROR)` | all | Moves cursor to an absolute offset. |
| `bytes_cursor_tell(cursor: HASH) -> (INTEGER, ERROR)` | all | Returns current cursor position. |
| `bytes_get(data: STRING\|BYTES, index: INTEGER) -> (INTEGER, ERROR)` | all | Reads one byte at index as integer. |
| `bytes_hex(value: INTEGER, width: INTEGER) -> (STRING, ERROR)` | all | Formats an integer as a zero-padded uppercase hex string with a 0x prefix (e.g. bytes_hex(4660, 8) -> "0x00001234"). This formats a number; it does not hex-encode a byte string. |
| `bytes_int_from_char(char: STRING) -> (INTEGER, ERROR)` | all | Converts a single-character string to its integer byte value. |
| `bytes_len(data: STRING\|BYTES) -> (INTEGER, ERROR)` | all | Returns length of a bytes value. |
| `bytes_read_u16_be(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 16-bit big-endian integer from bytes at offset. |
| `bytes_read_u16_le(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 16-bit little-endian integer from bytes at offset. |
| `bytes_read_u32_be(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 32-bit big-endian integer from bytes at offset. |
| `bytes_read_u32_le(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 32-bit little-endian integer from bytes at offset. |
| `bytes_read_u64_be(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 64-bit big-endian integer from bytes at offset. |
| `bytes_read_u64_le(data: STRING\|BYTES, offset: INTEGER) -> (INTEGER, ERROR)` | all | Reads unsigned 64-bit little-endian integer from bytes at offset. |
| `bytes_slice(data: STRING\|BYTES, start: INTEGER, length: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Returns a byte sub-slice of the given length starting at start (i.e. data[start:start+length]). |
| `bytes_to_string(b: STRING\|BYTES, encoding: STRING) -> (STRING, ERROR)` | all | Converts a buffer to text under a named encoding: "raw", "utf8" (validated), "latin1", "hex" or "base64". Returns (string, err). |
| `bytes_write_u16_be(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 16-bit big-endian integer into bytes at offset. |
| `bytes_write_u16_le(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 16-bit little-endian integer into bytes at offset. |
| `bytes_write_u32_be(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 32-bit big-endian integer into bytes at offset. |
| `bytes_write_u32_le(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 32-bit little-endian integer into bytes at offset. |
| `bytes_write_u64_be(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 64-bit big-endian integer into bytes at offset. |
| `bytes_write_u64_le(data: STRING\|BYTES, offset: INTEGER, value: INTEGER) -> (STRING\|BYTES, ERROR)` | all | Writes unsigned 64-bit little-endian integer into bytes at offset. |

## Archives (10)

Read evidence containers in place: `zip_*` for the .zip a KAPE, CyLR or Velociraptor collection arrives as, `tar_*` for the .tar and .tar.gz a Linux triage script produces (bzip2 and zstd too, detected by magic rather than by extension). Nothing is extracted to disk -- an entry goes straight into a BYTES buffer for whatever parses it next -- so the classic extraction escape cannot be exploited through these builtins. It is still reported: every entry carries `unsafe_path`, because an archive containing such a name is a finding in its own right. Every decompression is bounded, here and in `gunzip`/`zlib_decompress`, at 1000x its input and 1 GiB, which a caller can override per call with `max_bytes`.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `tar_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a tar handle and the archive file behind it. |
| `tar_entries(handle: STRING) -> ([]HASH, ERROR)` | all | Lists an archive's members from the walk tar_open already did: name, size, entry type, link target, POSIX mode/uid/gid/uname/gname, the three timestamps, and unsafe_path -- which covers a link target that escapes as well as a name that does. |
| `tar_open(path: STRING) -> (HASH, ERROR)` | all | Opens a tar archive -- plain, or wrapped in gzip, bzip2 or zstd, detected by magic rather than by extension -- and returns a handle. Tar has no central directory, so the whole archive is walked once here to learn what it contains; bodies are skipped rather than held. compression names what was detected. Release the handle with tar_close. |
| `tar_read(handle: STRING, name: STRING, max_bytes?: INTEGER) -> (STRING, ERROR)` | all | Reads one member by name and returns its contents as text. Tar has no index, so this walks from the start of the archive: cheap on a plain .tar, but on a compressed one it decompresses everything before the member, which makes reading many members quadratic. Limited to 1 GiB unless max_bytes says otherwise. Nothing is written to disk. |
| `tar_read_bytes(handle: STRING, name: STRING, max_bytes?: INTEGER) -> (BYTES, ERROR)` | all | Reads one member by name into a BYTES buffer. Same walk and same limits as tar_read; this is the form to use, since an archive member is binary unless proven otherwise. |
| `zip_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a zip handle and the archive file behind it. |
| `zip_entries(handle: STRING) -> ([]HASH, ERROR)` | all | Lists an archive's entries without decompressing any of them: name, sizes, compression method, CRC-32, mode, mtime, encryption flag, and unsafe_path. |
| `zip_open(path: STRING) -> (HASH, ERROR)` | all | Opens a zip archive (store/deflate/bzip2/zstd) and returns a handle for the other zip_ builtins. Reads the central directory only, so opening a large collection is cheap. unsafe_path_count reports entries whose names would escape a destination directory on extraction -- an archive that contains one is itself a finding. Release the handle with zip_close. |
| `zip_read(handle: STRING, name: STRING, max_bytes?: INTEGER) -> (STRING, ERROR)` | all | Reads one entry by name and returns its contents as text. Refuses to produce more than 1000x the entry's compressed size, capped at 1 GiB, unless max_bytes says otherwise -- the declared uncompressed size is checked first and the limit is enforced again against what actually decompresses, because a decompression bomb lies about its size. Nothing is written to disk. |
| `zip_read_bytes(handle: STRING, name: STRING, max_bytes?: INTEGER) -> (BYTES, ERROR)` | all | Reads one entry by name into a BYTES buffer. Same limits as zip_read; this is the form to use, since an archive member is binary unless proven otherwise. |

## Filesystem (20)

Read/write/manage files and directories, plus file-level forensics: hashing, entropy, string extraction, magic-type detection, carving, diffing, and NTFS deleted-file recovery.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `fs_append(path: STRING, data: STRING\|BYTES) -> (BOOLEAN, ERROR)` | all | Appends data to the end of a file. |
| `fs_carve(path: STRING, type: STRING) -> ([]HASH, ERROR)` | all | Scans a file for a known artifact signature and returns the byte offsets where it starts. It reports offsets only; it does not extract (carve out) the artifact bytes or determine their length. |
| `fs_copy(src: STRING, dst: STRING) -> (BOOLEAN, ERROR)` | all | Copies a file from source path to destination path. |
| `fs_delete(path: STRING) -> (BOOLEAN, ERROR)` | all | Deletes a file from disk. |
| `fs_deleted(path: STRING) -> (HASH, ERROR)` | all | Enumerates deleted files from an NTFS $MFT (a standalone $MFT file or a full volume image, auto-detected). A record is deleted when its in-use flag is clear but its metadata still parses. Small files with a resident $DATA attribute are fully recovered, as hex (resident_data) and as a buffer (resident_data_bytes) carrying the same bytes; larger non-resident files report metadata only. SI/FN times include unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns), and an RFC3339Nano iso string. Returns {source_type, deleted_count, skipped, entries:[{record, name, path, size, is_directory, has_data, resident, recoverable, resident_data, resident_data_bytes, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err). |
| `fs_diff(leftPath: STRING, rightPath: STRING) -> (HASH, ERROR)` | all | Compares two files (not directories) and reports differences. |
| `fs_entropy(path: STRING) -> (HASH, ERROR)` | all | Computes file entropy for packed/encrypted artifact detection. |
| `fs_exists(path: STRING) -> (BOOLEAN, ERROR)` | all | Returns whether a file or directory exists. |
| `fs_extract_strings(path: STRING, minLen?: INTEGER) -> ([]STRING, ERROR)` | all | Extracts printable strings from a file. |
| `fs_hash(path: STRING, algo?: STRING) -> (HASH, ERROR)` | all | Computes hash digests for a file. |
| `fs_list(path: STRING) -> ([]HASH, ERROR)` | all | Lists directory entries for a path. |
| `fs_magic(path: STRING) -> (HASH, ERROR)` | all | Infers file type/magic from a file's header against a ~40-signature database (executables PE/ELF/Mach-O, images, archives, documents, SQLite/registry/EVTX/pcap, media, and forensic artifacts like lnk/prefetch). Returns {path, type, mime, signature}. |
| `fs_metadata(path: STRING) -> (HASH, ERROR)` | all | Returns detailed filesystem metadata for a path. |
| `fs_mkdir(path: STRING) -> (BOOLEAN, ERROR)` | all | Creates a directory path. |
| `fs_move(src: STRING, dst: STRING) -> (BOOLEAN, ERROR)` | all | Moves or renames a file or directory. |
| `fs_read(path: STRING) -> (STRING, ERROR)` | all | Reads file contents from disk. |
| `fs_read_bytes(path: STRING) -> (BYTES, ERROR)` | all | Reads file contents from disk as a BYTES buffer. Use this rather than fs_read whenever the file is not known to be text. |
| `fs_stat(path: STRING) -> (HASH, ERROR)` | all | Returns file metadata such as size and timestamps. |
| `fs_walk(root: STRING, maxDepth?: INTEGER) -> ([]HASH, ERROR)` | all | Walks a directory tree and returns discovered paths. |
| `fs_write(path: STRING, data: STRING\|BYTES) -> (BOOLEAN, ERROR)` | all | Writes data to a file, replacing existing contents. |

## Network (33)

Sockets and TLS sessions, an in-process X.509 CA, HTTP-message inspection, listeners/serve loops, WebSocket framing, scanning, and offline pcap analysis. See [SECURE_NETWORKING.md](SECURE_NETWORKING.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `net_accept(listener: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Accepts one connection; returns {ok, handle, remote_addr, timeout, error}. |
| `net_banner(address: STRING, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Collects service banner text from a network endpoint. |
| `net_capture_raw(pcap_path: STRING) -> (HASH, ERROR)` | all | Reads raw packets from an offline pcap file into a per-packet listing (live interface capture needs cgo/raw sockets and is unavailable; net_pcap_analyze gives the flow summary, this gives the packets). Returns {file, link_type, count, truncated, packets:[{index, ts, timestamp, length, src, dst, protocol, sport, dport}]}. Returns (result, err). |
| `net_conn_close(handle: INTEGER) -> (BOOLEAN, ERROR)` | all | Closes a connection and releases its handle. |
| `net_conn_info(handle: INTEGER) -> (HASH, ERROR)` | all | Returns addressing and negotiated TLS session details for a connection. |
| `net_conn_read(handle: INTEGER, maxBytes: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads up to maxBytes from a connection; returns {data, bytes, eof, error} with I/O failures in the error field. |
| `net_conn_read_bytes(handle: INTEGER, maxBytes: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads up to maxBytes from a connection with `data` as a BYTES buffer; otherwise identical to net_conn_read. |
| `net_conn_write(handle: INTEGER, data: STRING, timeout_ms?: INTEGER) -> (INTEGER, ERROR)` | all | Writes bytes to a connection and returns the number written. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write. |
| `net_connect(address: STRING, timeoutMs: INTEGER) -> (INTEGER, ERROR)` | all | Opens a persistent TCP connection and returns a connection handle. |
| `net_connect_scan(host: STRING, startPort: INTEGER, endPort: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Scans a TCP port range on a host using full connect() probes (net.Dial). Pure-Go and unprivileged; not a half-open SYN scan (which needs raw sockets/privileges). |
| `net_dial(address: STRING, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Connectivity probe: dials address, immediately closes, and returns {ok, latency_ms, error}. Does not return a usable connection (use net_connect for that). |
| `net_dns_query(name: STRING, qtype: STRING) -> (STRING\|ARRAY, ERROR)` | all | Queries DNS records for a hostname. |
| `net_flow_reconstruct(packets: ARRAY) -> ([]HASH, ERROR)` | all | Reconstructs higher-level flows from packet records. |
| `net_listen(address: STRING) -> (INTEGER, ERROR)` | all | Opens a plain TCP listener and returns a listener handle. |
| `net_listen_close(handle: INTEGER) -> (BOOLEAN, ERROR)` | all | Closes a listener and releases its handle. |
| `net_os_fingerprint(pcap_path: STRING) -> (HASH, ERROR)` | all | Passively fingerprints OS families from TCP SYN/SYN-ACK packets in an offline pcap (p0f-style heuristic over TTL, DF, window, and TCP options). Identifies an OS family, not a definitive OS; runs offline with no privileges. |
| `net_pcap_analyze(path: STRING) -> (HASH, ERROR)` | all | Analyzes PCAP captures and returns flow/session signals. |
| `net_resolve(host: STRING) -> ([]STRING, ERROR)` | all | Resolves a host name to network addresses. |
| `net_serve(listener: INTEGER, handler_path: STRING, arg?) -> (NULL, ERROR)` | all | Accept loop that dispatches each connection to a fresh VM running handler_path; handler reads its connection via serve_conn() and shared arg via serve_arg(). Concurrent. |
| `net_spawn(handler_path: STRING, arg?) -> (BOOLEAN, ERROR)` | all | Runs handler_path on a new goroutine with no connection (serve_conn()->0) and arg via serve_arg(). For auxiliary workers, e.g. a WebSocket reverse pump. |
| `net_syn_scan(host: STRING, startPort: INTEGER, endPort: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | DEPRECATED alias of net_connect_scan. This is a full TCP connect scan, not a half-open SYN scan; use net_connect_scan. |
| `net_tls_connect(address: STRING, timeoutMs: INTEGER, options?: HASH\|STRUCT) -> (INTEGER, ERROR)` | all | Opens a TLS (secure) client connection and returns a connection handle. |
| `net_tls_fingerprint(address: STRING, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Collects TLS certificate and handshake fingerprint metadata. |
| `net_tls_listen(address: STRING, certPem: STRING, keyPem: STRING, options?: HASH\|STRUCT) -> (INTEGER, ERROR)` | all | Opens a TLS-terminating listener from a PEM cert/key pair. |
| `net_tls_upgrade_client(handle: INTEGER, options?: HASH\|STRUCT) -> (HASH, ERROR)` | all | Upgrades an open connection to client-side TLS (STARTTLS / upstream leg). |
| `net_tls_upgrade_server(handle: INTEGER, certPem: STRING, keyPem: STRING, options?: HASH\|STRUCT) -> (HASH, ERROR)` | all | Upgrades an accepted connection to server-side TLS (completes a CONNECT intercept). |
| `net_udp_scan(host: STRING, startPort: INTEGER, endPort: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Scans a UDP port range on a host. |
| `tls_generate_ca(options?: HASH\|STRUCT) -> (HASH, ERROR)` | all | Creates a self-signed CA certificate and key; returns {cert_pem, key_pem, serial}. |
| `tls_generate_cert(options?: HASH\|STRUCT) -> (HASH, ERROR)` | all | Creates a self-signed leaf/server certificate and key. |
| `tls_sign_cert(caCertPem: STRING, caKeyPem: STRING, options?: HASH\|STRUCT) -> (HASH, ERROR)` | all | Issues a leaf certificate signed by a CA (per-host interception cert). |
| `ws_accept_key(client_key: STRING) -> (STRING, ERROR)` | all | Computes the Sec-WebSocket-Accept value for an RFC 6455 101 handshake response. |
| `ws_read_frame(handle: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads one WebSocket frame (unmasked); returns {fin, opcode, payload, masked, length, is_control}. |
| `ws_write_frame(handle: INTEGER, opcode: INTEGER, payload: STRING, mask: BOOLEAN, timeout_ms?: INTEGER) -> (INTEGER, ERROR)` | all | Writes one WebSocket frame; mask=true for client->server, false for server->client. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write. |

## Http (11)

HTTP client requests and low-level request/response parsing and building for proxy/inspection workflows.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `http_build_request(request: HASH\|STRUCT) -> (STRING, ERROR)` | all | Serialises a request hash into HTTP wire bytes. |
| `http_build_response(response: HASH\|STRUCT) -> (STRING, ERROR)` | all | Serialises a response hash into HTTP wire bytes (adds Content-Length). |
| `http_conn_read_request(handle: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads exactly one HTTP request from a connection handle. |
| `http_conn_read_request_head(handle: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads a request's line+headers without the body (stream it via net_conn_read); adds content_length, chunked. |
| `http_conn_read_response(handle: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads exactly one HTTP response from a connection handle. |
| `http_conn_read_response_head(handle: INTEGER, timeoutMs: INTEGER) -> (HASH, ERROR)` | all | Reads a response's status line+headers without the body (stream it via net_conn_read); adds content_length, chunked. |
| `http_get(url: STRING) -> (HASH, ERROR)` | all | Performs an HTTP GET request. |
| `http_parse_request(raw: STRING) -> (HASH, ERROR)` | all | Parses a raw HTTP request into {method, url, path, host, proto, query, headers, body}. |
| `http_parse_response(raw: STRING) -> (HASH, ERROR)` | all | Parses a raw HTTP response into {status, status_text, proto, headers, body}. |
| `http_post(url: STRING, body: STRING\|HASH\|STRUCT, contentType?: STRING) -> (HASH, ERROR)` | all | Performs an HTTP POST request. contentType defaults to application/octet-stream when omitted. |
| `http_request(method: STRING, url: STRING, body: STRING\|HASH\|STRUCT, headers: HASH\|STRUCT) -> (HASH, ERROR)` | all | Performs an HTTP request with a body and a headers hash. All four arguments are required; the timeout is a fixed 30s (not configurable). |

## Graph Database (14)

Graph-oriented data modeling: typed nodes/edges, named relations, indexed artifact attributes, BFS traversal, shortest-path, statistics, and timelines. See [GRAPH_DATABASE.md](GRAPH_DATABASE.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `db_add_artifact(db: INTEGER, type: STRING, attrs?: HASH) -> (HASH, ERROR)` | all | Adds a forensic artifact node. type is a STRING; attrs is an optional properties hash that is indexed. |
| `db_add_edge(db: INTEGER, from: INTEGER, to: INTEGER, edgeType?: INTEGER\|ENUM_VALUE) -> (INTEGER, ERROR)` | all | Adds an edge between two node IDs. edgeType is an optional integer/enum edge type. Edge property hashes are not supported. |
| `db_add_node(db: INTEGER, nodeType?: INTEGER\|ENUM_VALUE) -> (INTEGER, ERROR)` | all | Adds a DATA node and returns its ID. nodeType is an optional integer/enum node type (0–127; 0 is the DATA type used when omitted). Property hashes are not supported. |
| `db_add_relation(db: INTEGER, from: INTEGER, to: INTEGER, relation: STRING) -> (HASH, ERROR)` | all | Adds a named relation edge between two entity IDs. All four arguments are required; property hashes are not supported. |
| `db_bfs(db: INTEGER, origin: INTEGER, depth: INTEGER, direction: STRING) -> (HASH, ERROR)` | all | Breadth-first traversal from origin up to depth. direction is "in", "out", or "both". All four arguments are required. |
| `db_close(db: INTEGER) -> (BOOLEAN, ERROR)` | all | Closes a graph database handle and flushes pending state. |
| `db_index_prop(db: INTEGER, nodeID: INTEGER, key: STRING, value: STRING) -> (BOOLEAN, ERROR)` | all | Indexes a property (key=value) on a node. All four arguments are required. |
| `db_open() -> (INTEGER, ERROR)` | all | Creates an in-memory graph database handle. |
| `db_open_disk(path: STRING) -> (INTEGER, ERROR)` | all | Opens or creates a disk-backed graph database. Note that compacting a store with this build rewrites it in a newer on-disk format that older mutant builds cannot open. |
| `db_query(db: INTEGER) -> ([]INTEGER, ERROR)` | all | Returns all DATA-type node IDs (an alias for db_query_nodes with no type filter). There is no query-expression language. |
| `db_query_nodes(db: INTEGER, nodeType?: INTEGER\|ENUM_VALUE) -> ([]INTEGER, ERROR)` | all | Returns node IDs, optionally filtered to a single node type (integer/enum). |
| `db_shortest_path(db: INTEGER, from: INTEGER, to: INTEGER) -> ([]INTEGER, ERROR)` | all | Computes shortest path between two graph nodes. |
| `db_stats(db: INTEGER) -> (HASH, ERROR)` | all | Returns graph database statistics: {nodes, edges, has_storage}. Disk-backed handles also report delta_records, csr_records, deleted_nodes, deleted_edges, wal_bytes, commit_seq and last_compact — growing delta_records/wal_bytes means the store is overdue for compaction. |
| `db_timeline(db: INTEGER) -> (ARRAY, ERROR)` | all | Returns chronological timeline events recorded in the graph. Takes only the handle (no options argument). |

## Cache (8)

In-memory key/value cache with TTLs and hit/miss statistics.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cache_clear(name: STRING) -> (INTEGER, ERROR)` | all | Clears all entries and resets relevant cache state. |
| `cache_close(name: STRING) -> (HASH, ERROR)` | all | Closes a named cache and frees its entries and backend. |
| `cache_delete(name: STRING, key: STRING) -> (BOOLEAN, ERROR)` | all | Deletes a key from cache and returns whether it existed. |
| `cache_get(name: STRING, key: STRING) -> (HASH, ERROR)` | all | Reads a value from cache and returns found/value fields. |
| `cache_keys(name: STRING) -> ([]STRING, ERROR)` | all | Lists sorted cache keys for a cache namespace. |
| `cache_open(name: STRING) -> (HASH, ERROR)` | all | Opens or creates a named in-memory cache store. |
| `cache_put(name: STRING, key: STRING, value, ttlSeconds?: INTEGER) -> (BOOLEAN, ERROR)` | all | Stores a value in a named cache key with optional TTL. |
| `cache_stats(name: STRING) -> (HASH, ERROR)` | all | Returns cache counters such as hits, misses, puts, deletes, and expires. |

## Policy (5)

Load and evaluate allow/deny policies with rule metadata and evaluation traces.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `policy_allow(policy: HASH\|STRING, input: HASH) -> (BOOLEAN, ERROR)` | all | Evaluates and returns allow/deny boolean for a policy. |
| `policy_eval(policy: HASH\|STRING, input: HASH) -> (HASH, ERROR)` | all | Evaluates a loaded policy and returns decision details. |
| `policy_load(name: STRING, source: HASH\|STRING) -> (HASH, ERROR)` | all | Loads a policy module by name from source text or config hash. |
| `policy_rules(policy: HASH\|STRING) -> (ANY, ERROR)` | all | Returns rule metadata exported by a loaded policy. |
| `policy_trace(policy: HASH\|STRING, input: HASH) -> (ANY, ERROR)` | all | Runs policy evaluation with trace output for debugging rule flow. |

## Runtime Integration (3)

Embed and securely execute Lua in a restricted sandbox (no `io`, dangerous `os.*` stripped, bounded execution). See [RUNTIME_INTEGRATION.md](RUNTIME_INTEGRATION.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `lua_run_file(path: STRING) -> (HASH, ERROR)` | all | Runs a Lua script from a file. |
| `lua_run_http(url: STRING) -> (HASH, ERROR)` | all | Fetches and runs a Lua script from an HTTP endpoint in a restricted sandbox (no io, no os.execute/exit/remove; only safe base/math/string/table/os-time libraries). |
| `lua_run_string(code: STRING) -> (HASH, ERROR)` | all | Runs a Lua script from a string. |

## Command Execution (4)

Guarded execution of external commands, subject to the `command_exec` capability policy.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cmd_add(builder: HASH, arg: STRING) -> (HASH, ERROR)` | all | Appends an argument to a command builder. |
| `cmd_builder(shell?: STRING) -> (HASH, ERROR)` | all | Creates a command builder object for step-wise command composition. |
| `cmd_run(builder: HASH) -> (HASH, ERROR)` | all | Executes a composed command and returns run output metadata. |
| `exec_string(command: STRING, shell?: STRING) -> (HASH, ERROR)` | all | Executes a shell command string via security-guarded command execution. |

## Cryptography (6)

X.509 certificate parsing, JWT decoding, PEM decoding, and authenticated AES-GCM encryption/decryption.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `aes_decrypt(key: STRING, ciphertext: STRING) -> (STRING, ERROR)` | all | AES-GCM decrypts ciphertext produced by aes_encrypt (nonce-prefixed). Returns (plaintext, err); errors on wrong key or tampering. |
| `aes_decrypt_bytes(key: STRING, ciphertext: STRING\|BYTES) -> (BYTES, ERROR)` | all | AES-GCM decrypts into a BYTES buffer. Recovered plaintext is binary until something proves otherwise, and a buffer is also the form the VM can wipe. Returns (plaintext, err). |
| `aes_encrypt(key: STRING, plaintext: STRING\|BYTES) -> (STRING, ERROR)` | all | AES-GCM encrypts plaintext. key must be 16/24/32 bytes. A random nonce is prepended to the output. Returns (ciphertext, err). |
| `jwt_decode(token: STRING) -> (HASH, ERROR)` | all | Decodes a JWT's header and claims WITHOUT verifying the signature (verified is always false). Returns {header, claims, algorithm, signature_present, verified}. Returns (result, err). |
| `pem_decode(s: STRING) -> (HASH, ERROR)` | all | Decodes the first PEM block. Returns {type, headers, der_hex, size, remaining_bytes}. Returns (result, err). |
| `x509_parse(pem_or_der: STRING) -> (HASH, ERROR)` | all | Parses an X.509 certificate (PEM or DER). Returns {subject, issuer, serial, not_before, not_after, is_ca, version, dns_names, ip_addresses, email_addresses, key_algorithm, signature_algorithm, sha1, sha256}. Returns (cert, err). |

## Fingerprinting (4)

Malware/host fingerprints: PE import hash (imphash), JA3 TLS-client fingerprint, and NTLM/LM password hashes (for authorized credential testing).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `imphash(pe_path: STRING) -> (HASH, ERROR)` | all | Computes the PE import hash (pefile/Mandiant algorithm) for malware clustering. Returns {imphash, import_count, dll_count}. Note: ordinal-only imports are rendered as ord<N>, so results may differ from VT for ws2_32/oleaut32 ordinal imports. Returns (result, err). |
| `ja3(client_hello: STRING) -> (HASH, ERROR)` | all | Computes the JA3 TLS-client fingerprint from a ClientHello (raw bytes, with or without the TLS record layer). Hashes version,ciphers,extensions,curves,point_formats with GREASE (RFC 8701) removed. Returns {ja3, ja3_hash (md5), tls_version, ciphers[], extensions[], curves[], point_formats[]}. Returns (result, err). |
| `lm_hash(password: STRING) -> STRING` | all | Returns the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex. Empty password -> aad3b435b51404eeaad3b435b51404ee. |
| `nt_hash(password: STRING) -> STRING` | all | Returns the NTLM NT hash (MD4 of the UTF-16LE password) as hex. For authorized credential testing/CTF use. |

## Network Intelligence (11)

IOC handling: defang/refang, IP/CIDR math, domain/eTLD+1 extraction, validation, and IOC extraction from free text.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cidr_hosts(cidr: STRING) -> []STRING` | all | Returns all addresses in a CIDR range (capped; errors if >20 host bits). |
| `defang(ioc: STRING) -> STRING` | all | Defangs an indicator for safe display (http->hxxp, .->[.], @->[at]). |
| `domain_extract(url: STRING) -> STRING` | all | Extracts the lowercased hostname from a URL or host string. |
| `extract_iocs(text: STRING) -> HASH` | all | Extracts IOCs from text (refanged first): {ipv4, urls, domains, emails, md5, sha1, sha256}, each unique and sorted. |
| `ip_in_cidr(ip: STRING, cidr: STRING) -> BOOLEAN` | all | Returns whether an IP falls within a CIDR range. |
| `ip_is_private(ip: STRING) -> BOOLEAN` | all | Returns whether an IP is private/loopback/link-local (RFC1918 etc.). |
| `ip_to_int(ip: STRING) -> INTEGER` | all | Converts an IPv4 address to its 32-bit integer form. |
| `ip_version(ip: STRING) -> INTEGER` | all | Returns 4, 6, or 0 (invalid) for an IP address. |
| `is_valid_domain(s: STRING) -> BOOLEAN` | all | Returns whether s is a syntactically valid domain name. |
| `refang(ioc: STRING) -> STRING` | all | Reverses common defang encodings ([.]/(.)/[dot]->., hxxp->http, [at]->@). |
| `tld_extract(domain: STRING) -> STRING\|HASH` | all | Returns {domain, etld1, suffix} using the public suffix list. |

## Detection (5)

Heuristic detectors for code injection, C2 beaconing, persistence, privilege escalation, and suspicious files, driven by supplied evidence.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `detect_injection(facts: HASH) -> (HASH, ERROR)` | all | Scores probable code injection in a memory image using multiple PE headers plus weighted shellcode signatures (GetPC via fnstenv/call-pop, PEB walks, NOP sleds); returns score and matched_signatures. |
| `detect_network_beacon(flows: ARRAY) -> (HASH, ERROR)` | all | Detects C2 beaconing by analyzing inter-arrival interval regularity (low coefficient of variation) and optional transfer-size consistency per destination; each flow may carry ts (epoch/RFC3339) and bytes. Returns per-dst score, interval_cv, and confidence. |
| `detect_persistence(facts: HASH) -> (HASH, ERROR)` | all | Detects persistence indicators from host evidence facts. |
| `detect_priv_esc(facts: HASH) -> (HASH, ERROR)` | all | Detects potential privilege-escalation indicators from host facts. |
| `detect_suspicious_files(paths: ARRAY) -> (HASH, ERROR)` | all | Flags suspicious files via entropy tiers (high/very-high), executable magic under a document extension (extension_mismatch), and disguised double extensions (e.g. invoice.pdf.exe). |

## Process Forensics (9)

Live process inspection: enumeration, tree, environment, open files, threads, modules, executable hashing, memory scanning, and signaling.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `process_env(pid?: INTEGER) -> (HASH, ERROR)` | all | Returns environment variables for a process (cross-platform; other processes may require privileges). |
| `process_hash(pid?: INTEGER) -> (HASH, ERROR)` | all | Computes SHA-256 hash metadata for a process executable. |
| `process_kill(pid: INTEGER, signal?: INTEGER) -> (BOOLEAN, ERROR)` | all | Sends a signal to a process (default SIGKILL semantics). |
| `process_list() -> ([]HASH, ERROR)` | all | Lists running processes (pid, ppid, name) natively on Windows, Linux, and macOS. |
| `process_memory_scan(pid: INTEGER, pattern: STRING) -> (HASH, ERROR)` | windows, linux | Scans a process's readable memory for a byte pattern and returns {pid, pattern, matched, truncated, addresses}. Real scan on Linux (/proc/self/mem) and Windows (VirtualQuery+ReadProcessMemory); self process only for now; honest error on macOS. |
| `process_modules(pid?: INTEGER) -> ([]STRING, ERROR)` | windows, linux | Lists loaded module/library paths for a process (memory maps on Linux, Toolhelp32 on Windows; fails honestly on platforms without a backend, e.g. macOS). |
| `process_open_files(pid?: INTEGER) -> ([]STRING, ERROR)` | all | Lists open file paths for a process (cross-platform; may require privileges for other processes). |
| `process_threads(pid?: INTEGER) -> (HASH, ERROR)` | all | Returns {pid, count, tids} for a process. The thread count is cross-platform; tids are populated where the OS exposes them (e.g. Linux). |
| `process_tree(rootPid?: INTEGER) -> (HASH, ERROR)` | all | Returns descendant processes for a root pid (default current process). Cross-platform, using real parent PIDs on every OS. |

## Memory Forensics (7)

Memory-dump analysis: segmentation with entropy, string extraction, pattern scanning, and PE/shellcode discovery.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `mem_find_pe(path: STRING) -> (HASH, ERROR)` | all | Finds PE headers in a memory image: carves each MZ marker and confirms real PEs by following e_lfanew to "PE\0\0". Returns {candidates, confirmed, headers:[{mz_offset, confirmed, pe_offset, machine}]}. |
| `mem_find_shellcode(path: STRING) -> ([]HASH, ERROR)` | all | Scans a memory dump file for common shellcode byte signatures. |
| `mem_map(path: STRING) -> ([]HASH, ERROR)` | all | Splits a memory dump into fixed-size (4 KiB) segments, each with measured entropy and printable-byte ratio. A raw dump carries no page-protection metadata, so no readable/writable/executable flags are reported. |
| `mem_read(path: STRING, offset: INTEGER, size: INTEGER) -> (HASH, ERROR)` | all | Reads a byte range from a memory image. |
| `mem_read_bytes(path: STRING, offset: INTEGER, size: INTEGER) -> (BYTES, ERROR)` | all | Reads a byte range from a memory image as a BYTES buffer. Unlike mem_read it returns the buffer itself rather than a hash: the offset is the one you asked for, and a short read at end-of-image is simply a shorter length. Prefer this whenever the range is going to be parsed rather than printed. |
| `mem_scan(path: STRING, pattern: STRING) -> (HASH, ERROR)` | all | Scans a memory image for a string/byte pattern. |
| `mem_strings(path: STRING, minLen?: INTEGER) -> ([]STRING, ERROR)` | all | Extracts printable strings from memory image data. |

## Binary Analysis (14)

PE/ELF/Mach-O/DWARF parsing, imports, sections, strings, entropy, literal signature scanning, and Go-binary metadata recovery (GoReSym).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bin_dwarf_parse(path: STRING) -> (HASH, ERROR)` | all | Parses DWARF metadata and reports compile unit information. |
| `bin_elf_parse(path: STRING) -> (HASH, ERROR)` | all | Parses ELF headers and returns core binary metadata. |
| `bin_entropy(path: STRING) -> (HASH, ERROR)` | all | Computes binary entropy signal. |
| `bin_imports(path: STRING) -> (HASH, ERROR)` | all | Returns imported symbols/libraries from a binary. |
| `bin_is_go(path: STRING) -> (HASH, ERROR)` | all | Quick check whether a binary was produced by the Go toolchain, using three signals (build info blob, Go build ID, and a parseable pclntab — the one that survives stripping). Returns {is_go, go_version, has_buildinfo, has_build_id, has_pclntab}. Returns (result, err). |
| `bin_macho_parse(path: STRING) -> (HASH, ERROR)` | all | Parses a Mach-O binary (macOS/iOS). Handles thin and fat/universal images. For a thin binary returns {format, fat, magic, cpu, type, flags, num_sections, num_commands, imported_libraries}; for a fat binary returns {format, fat, num_arches, architectures:[{cpu, type, offset, size, align}]}. Returns (result, err). |
| `bin_pe_parse(path: STRING) -> (HASH, ERROR)` | all | Parses PE headers and returns core binary metadata. |
| `bin_sections(path: STRING) -> (HASH, ERROR)` | all | Returns binary section table information. |
| `bin_strings(path: STRING, minLen?: INTEGER) -> ([]STRING, ERROR)` | all | Extracts printable strings from a binary. |
| `bin_yara_scan(path: STRING, rules: ARRAY, caseInsensitive?: BOOLEAN) -> (HASH, ERROR)` | all | Literal multi-string scan of a file (NOT a real YARA engine — that needs cgo). Reports every offset of each rule string. Case-sensitive unless caseInsensitive is true. Returns {engine, matched, total_hits, hits:[{rule, count, offsets}]}. |
| `go_build_id(path: STRING) -> (STRING, ERROR)` | all | Extracts the Go build ID from a binary. Returns (build_id, err). |
| `go_buildinfo(path: STRING) -> (HASH, ERROR)` | all | Extracts Go build info from a binary: go_version, module path, main module, dependencies (path/version/sum), and build settings (GOOS/GOARCH/vcs.*). Returns (info, err). |
| `go_symbols(path: STRING, mode?: STRING) -> (HASH, ERROR)` | all | Recovers function symbols from a Go binary via the pclntab — works even on STRIPPED binaries. Returns {go_version, arch, os, pclntab_va, function_count, user_function_count, std_function_count, functions:[{name, package, start, end, stdlib}]}. mode is "all" (default), "user", or "std". Returns (result, err). |
| `go_types(path: STRING) -> (HASH, ERROR)` | all | Recovers type and interface definitions from a Go binary via GoReSym typelink/itablink parsing, including reconstructed Go source for structs/interfaces where possible. Returns {go_version, type_count, itab_count, types:[{va, name, kind, reconstructed}], itabs:[...]}. Type recovery needs a parseable moduledata; GoReSym v1.7.1 supports it up to ~Go 1.24 and returns an honest error on newer toolchains. Returns (result, err). |

## Chain of Custody (8)

A case session that records who opened what, when, with which build of the tool. `case_open(id, examiner)` starts it; from there every evidence opener records its source into the manifest and every builtin that reads through an evidence handle is counted against that source. `case_verify` re-measures the sources and reports drift; `case_write` seals the manifest with a SHA-256 over its own contents and an Ed25519 signature, and `case_manifest_verify` checks both from the file alone. Nothing is recorded until a case is opened, so a program that does not use this is unaffected by it. The read-only guarantee the manifest asserts is machine-checked: see [EVIDENCE_HANDLING_POLICY.md](EVIDENCE_HANDLING_POLICY.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `case_close() -> (HASH, ERROR)` | all | Closes the case and returns its final manifest. After this, evidence openers stop recording. |
| `case_evidence(path: STRING, options?: HASH) -> (HASH, ERROR)` | all | Brings a file under custody that no evidence opener will touch -- a carved file, an export, a hash list handed over with the drive. Registers its size, modification time and, under the case's hash policy, its digest. |
| `case_manifest() -> (HASH, ERROR)` | all | Returns the case manifest as it stands: the case and examiner, the tool build, every evidence source with its size and digest, every builtin that touched each source with a count, the timeline, and the security telemetry for the run. Readable while the case is open and after it closes. |
| `case_manifest_verify(path: STRING) -> (HASH, ERROR)` | all | Checks a written manifest: that its contents still hash to the value in its seal, and that the signature over them holds. A function of the file alone -- it needs neither the case that produced it nor any key the reader does not already hold. |
| `case_note(text: STRING, data?) -> (HASH, ERROR)` | all | Records an examiner's note in the case timeline, with an optional value alongside it. The timeline holds what the analyst did -- opens, notes, verifications, the close -- and never grows with what the program read. |
| `case_open(id: STRING, examiner: STRING, options?: HASH) -> (HASH, ERROR)` | all | Opens a chain-of-custody session. From here until `case_close`, every evidence opener records its source into the case manifest and every builtin that reads through an evidence handle is counted against that source. Only one case may be open at a time. |
| `case_verify() -> (HASH, ERROR)` | all | Re-measures every source under custody and reports what moved. A case opened with a hash policy compares digests; one opened without compares size and modification time. Each source says which basis was used, so a weaker check is never mistaken for a stronger one. |
| `case_write(path: STRING, options?: HASH) -> (HASH, ERROR)` | all | Writes the manifest to disk as a signed JSON document. The seal carries a SHA-256 over every field except itself and an Ed25519 signature over the same bytes, from the local key pair Mutant already maintains; the public key travels in the document, so `case_manifest_verify` needs nothing but the file. |

## Registry Forensics (15)

Windows registry across three sources via one polymorphic API (regf hive file, hive-JSON, or live Windows registry), plus Amcache and Shimcache execution evidence.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `amcache_parse(path: STRING) -> (HASH, ERROR)` | all | Parses an Amcache.hve hive (program execution/presence evidence) into {format, count, entries:[{key, path, name, sha1, publisher, version, product, size, last_write}]}. Supports the modern InventoryApplicationFile and legacy Root\File layouts. Returns (result, err). |
| `hive_close(handle: STRING) -> (BOOLEAN, ERROR)` | all | Closes a hive handle. Returns (bool, err). |
| `hive_get_value(handle: STRING, keypath: STRING, name: STRING) -> (HASH, ERROR)` | all | Returns {name, type, data} for a single value under keypath. Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. Returns (result, err). |
| `hive_key_info(handle: STRING, keypath?: STRING) -> (HASH, ERROR)` | all | Returns {name, last_write, last_write_iso, subkey_count, value_count} for a key (keypath is backslash-separated under the root; default root). Returns (result, err). |
| `hive_list_keys(handle: STRING, keypath?: STRING) -> ([]STRING, ERROR)` | all | Returns the subkey names under a key (default root) as an array. Returns (array, err). |
| `hive_list_values(handle: STRING, keypath?: STRING) -> ([]HASH, ERROR)` | all | Returns a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. Returns (array, err). |
| `hive_open(path: STRING) -> (HASH, ERROR)` | all | Opens a real Windows registry hive (regf binary format — SOFTWARE/SYSTEM/NTUSER.DAT, etc.) and returns {handle, path}. Distinct from the JSON-fixture reg_* family. Returns (result, err). |
| `reg_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a registry-hive handle opened with reg_open. |
| `reg_deleted_keys(handle: STRING) -> (ARRAY, ERROR)` | all | Lists deleted-key entries. Populated only for the JSON source (its deleted_keys field); empty for real hive files and live registry (no unallocated-cell carving). |
| `reg_enum_keys(handle: STRING, keyPath?: STRING) -> ([]STRING, ERROR)` | all | Enumerates subkeys under a key. For hive/live sources keyPath is relative to the opened key (default root); for JSON it is the absolute path. Returns (array, err). |
| `reg_enum_values(handle: STRING, keyPath?: STRING) -> ([]HASH, ERROR)` | all | Enumerates a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. A JSON source never reports one, having no binary type to transcribe. Works across JSON/hive-file/live sources. Returns (array, err). |
| `reg_get_value(handle: STRING, keyPath: STRING, valueName: STRING) -> (HASH, ERROR)` | all | Reads a specific registry value with type metadata, across JSON/hive-file/live sources. Binary values (REG_BINARY, and types the reader does not recognise) also carry data_bytes, the stored bytes as a BYTES buffer; other types omit it, since data already holds the value faithfully. A JSON source never reports one, having no binary type to transcribe. Returns (result, err). |
| `reg_open(source: STRING) -> (HASH, ERROR)` | all | Opens a registry data source (polymorphic) and returns {handle, path, source_type, status}. Dispatch: a regf hive file (SOFTWARE/SYSTEM/NTUSER.DAT, …) -> real hive parse; a hive-JSON file -> JSON; otherwise a live Windows registry path (e.g. HKLM\SOFTWARE\...) -> live registry (Windows only). Returns (result, err). |
| `reg_timeline(handle: STRING) -> (ARRAY, ERROR)` | all | Returns timeline entries. Populated only for the JSON source (its timeline field); empty for real hive files and live registry. |
| `shimcache_parse(path: STRING) -> (HASH, ERROR)` | all | Decodes the Windows AppCompatCache (shimcache) — program execution/presence evidence. Accepts a SYSTEM hive file (locates the value) or a raw AppCompatCache blob. Supports Win8/Win8.1/Win10 (10ts/00ts). Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}. Returns (result, err). |

## Filesystem Forensics (37)

Read-only filesystem parsers for NTFS/FAT/exFAT/ext/HFS+/XFS images and standalone $MFT timelines, with rich MAC timestamps and metadata.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `ext_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an ext handle and releases its file. |
| `ext_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened ext image, with created_at/modified_at/accessed_at/changed_at and deleted. |
| `ext_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete). |
| `ext_open(image: STRING) -> (HASH, ERROR)` | all | Opens an ext2/3/4 filesystem image and returns a handle. Returns (result, err). |
| `ext_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened ext image. |
| `ext_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened ext image as a BYTES buffer. |
| `fat_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a FAT handle and releases its file. |
| `fat_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened FAT image. |
| `fat_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a path in an opened FAT image. |
| `fat_open(image: STRING) -> (HASH, ERROR)` | all | Opens a FAT filesystem image and returns a handle. Returns (result, err). |
| `fat_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened FAT image. |
| `fat_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened FAT image as a BYTES buffer. |
| `hfs_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an HFS+ handle and releases its file. |
| `hfs_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened HFS+ image. |
| `hfs_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size. |
| `hfs_open(image: STRING) -> (HASH, ERROR)` | all | Opens an HFS+ filesystem image and returns a handle. Returns (result, err). |
| `hfs_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened HFS+ image. |
| `hfs_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened HFS+ image as a BYTES buffer. |
| `mft_parse(path: STRING) -> (HASH, ERROR)` | all | Parses an NTFS Master File Table into a per-record timeline. Auto-detects a standalone $MFT file (FILE-signature record stream, e.g. KAPE/FTK/icat) vs a full NTFS volume image. Each entry has $STANDARD_INFORMATION (si_*) and $FILE_NAME (fn_*) MAC times as unix seconds, a sub-second nanosecond fraction (si_*_ns/fn_*_ns, 0-999999999, at NTFS 100 ns resolution — a whole-second/zero fraction is a timestomping tell), and an RFC3339Nano iso string; plus reconstructed path, size, sequence, and hard-link count. The record size is read from the first record header rather than assumed, and skipped counts records that would not parse. Returns {source_type, record_size, count, skipped, entries:[{record, parent_record, in_use, is_directory, name, path, size, allocated_size, sequence, hard_links, file_attributes, si_*, si_*_ns, fn_*, fn_*_ns}]}. Returns (result, err). |
| `ntfs_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an NTFS handle and releases its file. |
| `ntfs_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened NTFS image. |
| `ntfs_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error). |
| `ntfs_open(image: STRING) -> (HASH, ERROR)` | all | Opens an NTFS filesystem image and returns a handle. Returns (result, err). |
| `ntfs_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened NTFS image. |
| `ntfs_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened NTFS image as a BYTES buffer. |
| `xfat_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an exFAT handle and releases its file. |
| `xfat_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened exFAT image, with created_at/modified_at/accessed_at, per-timestamp *_utc_offset_valid flags, attributes and valid_data_size. A nameless entry is reported as "(unnamed)". |
| `xfat_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack). |
| `xfat_open(image: STRING) -> (HASH, ERROR)` | all | Opens an exFAT filesystem image and returns a handle. Returns (result, err). |
| `xfat_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened exFAT image. Content is staged through a temporary file because libxfat extracts to a path, so reads are capped at 32 MiB. |
| `xfat_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened exFAT image as a BYTES buffer. Content is staged through a temporary file, so reads are capped at 32 MiB. |
| `xfs_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an XFS handle and releases its file. |
| `xfs_list_files(handle: STRING, dir: STRING) -> ([]HASH, ERROR)` | all | Lists entries under a directory in an opened XFS image, with file_type from the directory record. A damaged inode no longer aborts the listing: that entry is reported with inode_error set and size 0. |
| `xfs_metadata(handle: STRING, path: STRING) -> (HASH, ERROR)` | all | Returns metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion). |
| `xfs_open(image: STRING) -> (HASH, ERROR)` | all | Opens an XFS filesystem image and returns a handle. Returns (result, err). |
| `xfs_read_file(handle: STRING, path: STRING) -> (STRING, ERROR)` | all | Reads a file's bytes from an opened XFS image. |
| `xfs_read_file_bytes(handle: STRING, path: STRING) -> (BYTES, ERROR)` | all | Reads a file from an opened XFS image as a BYTES buffer. |

## Disk Image Forensics (20)

Container and partition-table parsers: raw images, EWF/E01, VHD/VHDX (with differencing chains), and MBR/GPT partition tables.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `ewf_close(handle: STRING) -> (HASH, ERROR)` | all | Closes an EWF handle and its segment files. |
| `ewf_metadata(handle: STRING) -> (HASH, ERROR)` | all | Returns EWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method). chunk_tables_invalid counts chunk-table groups that failed both their primary and backup checksum — their data decoded unverified and should be treated as suspect; chunk_tables_recovered, observed_chunk_count and acquisition_error_count report the rest of the integrity picture. |
| `ewf_open(segments: STRING\|ARRAY) -> (HASH, ERROR)` | all | Opens an EWF/E01 image (a segment path or an array of segment paths). Returns (result, err). |
| `ewf_read_at(handle: STRING, offset: INTEGER, length: INTEGER) -> (STRING, ERROR)` | all | Reads length bytes at an offset from an EWF image (length capped at 32 MiB). |
| `ewf_read_at_bytes(handle: STRING, offset: INTEGER, length: INTEGER) -> (BYTES, ERROR)` | all | Reads length bytes at an offset from an EWF image as a BYTES buffer (length capped at 32 MiB). |
| `raw_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a raw image handle. |
| `raw_metadata(handle: STRING) -> (HASH, ERROR)` | all | Returns {file_size, assumed_sector_size, sector_size_assumed} (raw images carry no real sector-size metadata). |
| `raw_open(image: STRING) -> (HASH, ERROR)` | all | Opens a raw disk image and returns a handle. Returns (result, err). |
| `raw_read_at(handle: STRING, offset: INTEGER, length: INTEGER) -> (STRING, ERROR)` | all | Reads length bytes at an offset from a raw image (length capped at 32 MiB). |
| `raw_read_at_bytes(handle: STRING, offset: INTEGER, length: INTEGER) -> (BYTES, ERROR)` | all | Reads length bytes at an offset from a raw image as a BYTES buffer (length capped at 32 MiB). |
| `table_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a partition-table handle. |
| `table_list_partitions(handle: STRING) -> ([]HASH, ERROR)` | all | Lists partitions with LBA ranges, absolute start_byte/length_byte, type, name, flags, and hex type_code/attributes. Use start_byte rather than start_lba * block_size, which mislocates every partition on a table parsed at a non-zero offset. |
| `table_open(image: STRING) -> (HASH, ERROR)` | all | Opens a disk image and parses its partition table(s) (MBR/GPT). warnings reports suspicious-but-parsable findings (out-of-bounds entries, overlapping extents, hybrid MBR, truncated entry counts); candidates lists every scheme that parsed cleanly, so more than one means the media was ambiguous. Returns (result, err). |
| `table_partition_info(handle: STRING, index: INTEGER) -> (HASH, ERROR)` | all | Returns details for a single partition by index, including absolute start_byte/length_byte. |
| `vhdi_close(handle: STRING) -> (HASH, ERROR)` | all | Closes a VHD/VHDX handle. |
| `vhdi_map_offset(handle: STRING, offset: INTEGER) -> (HASH, ERROR)` | all | Maps a virtual offset to a backing file offset. Returns {virtual_offset, mapped, file_offset}. |
| `vhdi_metadata(handle: STRING) -> (HASH, ERROR)` | all | Returns VHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed). |
| `vhdi_open(image: STRING) -> (HASH, ERROR)` | all | Opens a VHD/VHDX disk image and returns a handle. Returns (result, err). |
| `vhdi_read_at(handle: STRING, offset: INTEGER, length: INTEGER) -> (STRING, ERROR)` | all | Reads length bytes at a virtual offset from a VHD/VHDX image (length capped at 32 MiB). |
| `vhdi_read_at_bytes(handle: STRING, offset: INTEGER, length: INTEGER) -> (BYTES, ERROR)` | all | Reads length bytes at a virtual offset from a VHD/VHDX image as a BYTES buffer (length capped at 32 MiB). |

## Windows Artifacts (5)

Execution and shell-activity artifacts: Prefetch, Windows Event Logs (EVTX), shell links (LNK), and Jump Lists.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `evtx_parse(path: STRING) -> (HASH, ERROR)` | all | Parses a Windows Event Log (.evtx). Walks every chunk and decodes each record's BinXML (templates + substitutions) into the fully-expanded event tree, plus summary fields per record. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err). |
| `evtx_parse_bytes(path: STRING) -> (HASH, ERROR)` | all | Parses a Windows Event Log (.evtx) exactly as evtx_parse does, except that binary event values (EVTX BinaryType) come back as BYTES buffers instead of hex strings. Everything else -- the record tree, the summary fields, the return shape -- is identical. Use this when an event carries a binary payload you intend to read rather than print. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err). |
| `jumplist_parse(path: STRING) -> (HASH, ERROR)` | all | Parses a Windows Jump List (recent/pinned destinations). Auto-detects *.automaticDestinations-ms (OLE compound file: numbered shell-link streams + a DestList MRU/metadata stream) and *.customDestinations-ms (concatenated shell links). Each entry merges DestList metadata (last_access, pinned, hostname) with the embedded shell-link target. Returns {type, format_version, entry_count, pinned_count, entries:[{stream_id, target, arguments, working_dir, name, last_access, last_access_iso, pinned, hostname}]}. Returns (result, err). |
| `lnk_parse(path: STRING) -> (HASH, ERROR)` | all | Parses a Windows shell link (.lnk): header (attributes, creation/access/write FILETIME->unix), decoded LinkFlags, LinkInfo local_base_path (target), and StringData (name, relative_path, working_dir, arguments, icon_location). Returns (result, err). |
| `prefetch_parse(path: STRING) -> (HASH, ERROR)` | all | Decodes a Windows Prefetch (.pf) file — program execution evidence. Transparently decompresses the Win10/11 MAM (Xpress-Huffman) container and parses the SCCA format for XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31). Returns {version, executable, prefetch_hash, run_count, run_times[], files_loaded[], file_count, volumes:[{device_path, serial, created, created_iso}], compressed}. Returns (result, err). |

## Unix Artifacts (1)

Unix log artifacts: RFC 5424 / RFC 3164 syslog parsing.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `syslog_parse(path: STRING) -> (HASH, ERROR)` | all | Parses a Unix syslog file into structured entries, auto-detecting RFC 5424 (IETF, ISO-8601) and RFC 3164 (BSD) per line; unmatched lines are kept as raw messages. RFC 3164 lines omit the year, so the current year is assumed. Each entry has a `ts` unix field for timeline_merge/timeline_sort. Returns {count, entries:[{format, priority, facility, severity, timestamp, ts, host, app_name, pid, msgid, structured_data, message}]}. Returns (result, err). |

## Browser Artifacts (5)

Chromium/Firefox history, cookies, and downloads, plus generic read-only SQLite querying (forensically safe: originals are never modified).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `browser_cookies(path: STRING) -> (HASH, ERROR)` | all | Parses a Chromium (Cookies) or Firefox (cookies.sqlite) cookie database. Chromium cookie values are OS-encrypted; such rows are reported with encrypted=true and an empty value (decryption needs OS keys). Returns {browser, count, entries:[{host, name, value, path, expires, expires_iso, secure, http_only, encrypted, browser}]}. Returns (result, err). |
| `browser_downloads(path: STRING) -> (HASH, ERROR)` | all | Parses download records from a Chromium (History downloads table) or Firefox (places.sqlite moz_annos) database; Firefox support is best-effort (destination file URI). Returns {browser, count, entries:[{url, target_path, bytes_total, bytes_received, start_time, end_time, state, mime_type, browser}]}. Returns (result, err). |
| `browser_history(path: STRING) -> (HASH, ERROR)` | all | Parses a Chromium (History) or Firefox (places.sqlite) history database into normalized visit entries, auto-detecting the schema and converting timestamps to unix. Returns {browser, count, entries:[{url, title, visit_count, last_visit, last_visit_iso, browser}]}. Returns (result, err). |
| `sqlite_query(path: STRING, sql: STRING, params?: ARRAY) -> (HASH, ERROR)` | all | Runs a read-only SQL query against a SQLite database, pure-Go (no cgo). The database (+ any -wal/-shm sidecars) is copied to a temp file first, so the original is never modified or lock-contended — safe for forensic DBs held open by a running app. Optional params is an ARRAY of bind values for a parameterized query. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err). |
| `sqlite_query_bytes(path: STRING, sql: STRING, params?: ARRAY) -> (HASH, ERROR)` | all | Runs a read-only SQL query exactly as sqlite_query does, except that BLOB columns come back as BYTES buffers. sqlite_query asks whether a BLOB happens to be valid UTF-8 and returns a string if so and hex if not, so one column's type varies row by row with its content; here a BLOB is a buffer whatever it holds. Other column types are unchanged: INTEGER is an INT, TEXT a STRING, NULL a NULL. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err). |

## Forensic Timeline (5)

Normalize timestamps across epochs and merge/sort artifact events into a single supertimeline; Sleuth Kit bodyfile/mactime interop.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bodyfile_parse(path: STRING) -> ([]HASH, ERROR)` | all | Parses a Sleuth Kit bodyfile (MD5\|name\|inode\|mode\|UID\|GID\|size\|atime\|mtime\|ctime\|crtime) into an array of entry hashes. Returns (entries, err). |
| `mactime(entries: ARRAY) -> []HASH` | all | Builds a chronological MAC-time timeline from bodyfile_parse entries: one row per distinct time with a MACB flag string (m/a/c/b, "." where absent), sorted by ts then name (ts field composes with timeline_merge). |
| `timeline_merge(sources: ARRAY, field?: STRING) -> ARRAY` | all | Flattens an array of event arrays into one supertimeline sorted by a numeric timestamp field (default "ts"). |
| `timeline_sort(events: ARRAY, field?: STRING) -> ARRAY` | all | Returns events (array of hashes) sorted ascending by a numeric timestamp field (default "ts"); events missing the field sort last. Stable. |
| `timestamp_normalize(value: INTEGER\|STRING, format?: STRING) -> (HASH, ERROR)` | all | Normalizes a timestamp to {unix, unix_ms, iso, format}. Formats: unix (s/ms/us/ns), filetime (Windows), webkit/chrome, dos (packed 32-bit), iso (RFC3339 string). Default "auto" detects unix magnitude or parses an ISO string. Returns (result, err). |

## Schema Interchange (5)

Normalize any parsed artifact into one event vocabulary, then write that vocabulary out in whichever schema the next tool reads. `events_from` maps an artifact's entries onto a fixed set of event fields -- one event per timestamp the artifact recorded, with the source entry carried verbatim in `extra` so nothing is lost -- and `event_kinds()` reports what each supported artifact maps. `ecs_event`, `ocsf_event` and `timesketch_event` render those events as Elastic Common Schema documents, OCSF events, or the plaso records Timesketch ingests, one event or a whole timeline at a time. Thirteen artifacts and three schemas cost sixteen mappings here rather than thirty-nine, so a new parser reaches every schema by describing itself once. An artifact Mutant does not know is described with a mapping hash rather than waiting for support. See [INTERCHANGE_SCHEMAS.md](INTERCHANGE_SCHEMAS.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `ecs_event(event: HASH\|ARRAY, opts?: HASH) -> (HASH\|ARRAY, ERROR)` | all | Renders events_from() events as Elastic Common Schema documents: one ECS document, or one per event when given a whole timeline. Maps the envelope onto @timestamp, event.*, host/user, file.*, process.*, source/destination.*, url.full and registry.path; keeps the severity word in log.level beside a syslog-scale event.severity; and carries what ECS does not define under a `mutant` namespace -- including ts_desc, without which the four documents an $MFT record produces are the same document four times, and the verbatim source entry in mutant.extra. A field the artifact did not record is omitted rather than emitted empty. A category ECS has no honest home for, log among them, leaves event.category out rather than filing the document under the wrong one. Returns (document(s), err). |
| `event_kinds() -> []HASH` | all | Lists the artifact kinds events_from understands, each with the envelope category and action it maps to, the key its entries live under, the timestamps it reads and what each one means, and the envelope fields it fills. |
| `events_from(artifact: HASH\|ARRAY, kind_or_mapping: STRING\|HASH) -> ([]HASH, ERROR)` | all | Normalizes a parsed artifact into interchange events: one event per timestamp the artifact records, in a fixed vocabulary the ECS/OCSF/Timesketch emitters are written against. The second argument names a built-in source kind (event_kinds() lists them) or is a mapping hash {kind, category, action, entries, message, times:[{field, desc, format?, ns_field?, array?}], fields:{envelope: source}} describing an artifact this tree does not know. Unknown fields are omitted rather than emitted empty, a zero timestamp yields no event, and `extra` carries the source entry verbatim so normalizing loses nothing. Accepts a parser's (result, err) pair directly. Returns (events, err). |
| `ocsf_event(event: HASH\|ARRAY, opts?: HASH) -> (HASH\|ARRAY, ERROR)` | all | Renders events_from() events as OCSF 1.1 events: one event, or one per event when given a whole timeline. The class comes from the envelope category -- file to 1001 File System Activity, web to 6001, network to 4001, authentication to 3002 -- and anything with no honest fit, execution and registry included, stays on the Base Event 0/0 rather than borrowing a class someone else's detection rule fires on. activity_id is read from what the timestamp records, so a creation time becomes Create and an access time becomes Read; the severity word maps straight onto severity_id, which is why the envelope carries a word. What OCSF has no home for -- the kind, the timestamp description, the verbatim source entry -- goes in `unmapped`, the field OCSF keeps for exactly that. Returns (event(s), err). |
| `timesketch_event(event: HASH\|ARRAY, opts?: HASH) -> (HASH\|ARRAY, ERROR)` | all | Renders events_from() events as Timesketch/plaso records, ready for ndjson_stringify: one record, or one per event when given a whole timeline. Fills all three fields Timesketch requires -- message, datetime, timestamp_desc -- and never leaves one empty, because a record missing any of them is dropped on ingest rather than flagged. `timestamp` counts plaso microseconds. `data_type` is the plaso string its analyzers key off (mft to fs:stat:ntfs, prefetch to windows:prefetch:execution, the browser kinds by which browser the entry came out of); a kind with no plaso equivalent gets mutant:<kind>:event rather than borrowing one an analyzer would then run over and report on. Returns (record(s), err). |

## Email Forensics (5)

Parse raw email into headers/body/attachments/URLs and cryptographically verify DKIM (with SPF/DMARC reporting).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `email_attachments(raw: STRING) -> ([]HASH, ERROR)` | all | Extracts attachment metadata/content details from raw email input. |
| `email_headers(raw: STRING) -> (HASH, ERROR)` | all | Parses and returns message headers from raw email input. |
| `email_parse(raw: STRING) -> (HASH, ERROR)` | all | Parses a raw email message into headers, body parts, and attachments. |
| `email_spf_dkim(raw: STRING) -> (HASH, ERROR)` | all | Cryptographically verifies DKIM signatures (public key via DNS) and reports SPF/DMARC. SPF is reported as recorded by the receiving MTA; DMARC combines the reported result with DKIM alignment. |
| `email_urls(raw: STRING) -> ([]HASH, ERROR)` | all | Extracts and normalizes URLs from email headers and body. |

## Hash-Set Forensics (3)

NSRL-style known-file hash sets for include/exclude filtering.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `hashset_close(handle: STRING) -> (BOOLEAN, ERROR)` | all | Frees a loaded hash set. Returns (bool, err). |
| `hashset_contains(handle: STRING, hash: STRING) -> (BOOLEAN, ERROR)` | all | Returns whether a hash is in a loaded set (case-insensitive). Returns (bool, err). |
| `hashset_load(path: STRING) -> (HASH, ERROR)` | all | Loads a file of hashes (one per line, or CSV/NSRL where the hash is the first field) into an in-memory set. Skips headers/comments/non-hex. Returns {handle, count}. Returns (result, err). |
