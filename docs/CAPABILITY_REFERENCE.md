# Mutant Capability Reference

> Generated from the builtin metadata (`builtin/metadata.go`) — the source of truth.
> To refresh after adding or changing builtins, iterate `builtin.Builtins` and read
> each entry's `TeachingDoc`, `PlatformSupport`, and `CapabilityCategory`. Prefer
> regenerating over hand-editing the tables so signatures and counts never drift.

This is the canonical, category-grouped catalog of every Mutant builtin. There are currently **399 registered builtins** across **32 capability categories**. For language syntax and keywords see [MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md); deep-dive guides are linked per category below.

## How to read this reference

- **Fallible builtins return a `(value, err)` pair**, matching the language idiom `let value, err = some_call(...);`. Check `err` before using `value`. Infallible helpers return a bare value.
- **The Platforms column** lists the operating systems a builtin actually works on. `all` means it is pure-Go and cross-platform (it operates on captured artifacts, so it runs on any host). A restricted set (e.g. `windows/linux`) means the builtin fails honestly elsewhere — and the language server will flag such a call when you are editing on an unsupported OS (the `platformSupport` diagnostic).
- **Pure-Go, no cgo.** The entire standard library builds and runs with `CGO_ENABLED=0` on Windows, Linux, and macOS.

## Platform-restricted builtins

Almost every builtin is cross-platform. The exceptions:

| Builtin | Platforms | Note |
| --- | --- | --- |
| `process_memory_scan` | windows, linux | fails honestly on other platforms |
| `process_modules` | windows, linux | fails honestly on other platforms |

`reg_open` and `process_kill` work on all platforms but have Windows-specific behavior in one path; hover in the editor shows the note.

---

## Standard Library (54)

Core language primitives: collection and hash operations, first-class higher-order functions (`map`/`filter`/`reduce`/`each`/`sort_by`), math helpers, I/O, and runtime/security introspection.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `abs(x)` | all | Absolute value (preserves INTEGER/FLOAT type). |
| `avg(array)` | all | Arithmetic mean of a numeric array (FLOAT); errors on empty. |
| `ceil(x)` | all | Smallest integer >= x (INTEGER). |
| `clamp(x, lo, hi)` | all | Constrains x to the range [lo, hi]. |
| `concat(a, b)` | all | Returns a new array with the elements of a followed by b. |
| `contains(array, value)` | all | Returns whether array contains value (by value equality). |
| `debug_status()` | all | Returns runtime/debugger status information. |
| `delete(hash, key)` | all | Returns a new hash with key removed. |
| `each(array, fn)` | all | Calls fn for each element for its side effects and returns null. fn takes (element) or (element, index). |
| `entries(hash)` | all | Returns the hash as an array of [key, value] pairs (sorted by key). |
| `filter(array, fn)` | all | Returns a new array of the elements for which fn is truthy. fn takes (element) or (element, index). |
| `first(array)` | all | Returns the first element of an array. |
| `flatten(array)` | all | Flattens one level of nested arrays. |
| `floor(x)` | all | Largest integer <= x (INTEGER). |
| `get(hash, key, default)` | all | Returns hash[key], or default when the key is absent. |
| `gets()` | all | Reads a full line of input from stdin and returns it as a STRING (newline trimmed). Use to_int/to_float/parse_int to convert. |
| `has_key(hash, key)` | all | Returns whether hash contains key. |
| `help(topic?, mode?)` | all | Returns help text: an overview, a topic (keywords/builtins/examples/docs), or details for a specific builtin name. |
| `index_of(array, value)` | all | Returns the first index of value in array, or -1. |
| `int_to_ip(n)` | all | Converts a 32-bit integer to an IPv4 dotted-quad string. |
| `is_null(v)` | all | Returns whether v is NULL. |
| `keys(hash)` | all | Returns the hash keys as an array (sorted for determinism). |
| `last(array)` | all | Returns the last element of an array. |
| `len(value)` | all | Returns the length of a string, array, hash, or bytes value. |
| `map(array, fn)` | all | Returns a new array of fn applied to each element. fn takes (element) or (element, index). |
| `max(...values)` | all | Returns the largest of the numeric arguments (original type preserved). |
| `merge(a, b)` | all | Returns a new hash combining a and b (b wins on key conflicts). |
| `min(...values)` | all | Returns the smallest of the numeric arguments (original type preserved). |
| `mod(a, b)` | all | Returns a modulo b; errors on b=0. Integer mod when both are INTEGER. |
| `pop(array)` | all | Returns a new array without the last element. |
| `pow(x, y)` | all | Returns x raised to the power y (FLOAT). |
| `push(array, value)` | all | Returns a new array with value appended. |
| `putf(format, ...values)` | all | Formats and prints values using a format string. |
| `putln(value)` | all | Prints a value followed by a newline. |
| `range(start, end, step?)` | all | Returns an array of integers from start (inclusive) to end (exclusive); step defaults to 1. |
| `reduce(array, fn, initial)` | all | Folds the array to a single value: fn(accumulator, element) starting from initial. |
| `rest(array)` | all | Returns a new array without the first element. |
| `reverse(array)` | all | Returns a reversed copy of an array. |
| `round(x)` | all | Nearest integer to x (INTEGER). |
| `sandbox_status()` | all | Returns sandbox-detection status information. |
| `security_diagnostics()` | all | Returns security diagnostics for the current runtime. |
| `serve_arg()` | all | Inside a net_serve handler, returns the shared arg passed to net_serve; null otherwise. |
| `serve_conn()` | all | Inside a net_serve handler, returns the connection handle (INTEGER); null otherwise. |
| `set(hash, key, value)` | all | Returns a new hash with key set to value (original unchanged). |
| `sleep_ms(ms)` | all | Blocks the current handler for ms milliseconds. |
| `slice(array, start, end)` | all | Returns the sub-array array[start:end] (bounds-clamped). |
| `sort(array)` | all | Returns a sorted copy of an array (all numbers or all strings). |
| `sort_by(array, fn)` | all | Returns a new array stably sorted by the key fn returns for each element (INTEGER/FLOAT/STRING keys). |
| `sqrt(x)` | all | Returns the square root of x (FLOAT); errors on negative x. |
| `sum(array)` | all | Sum of a numeric array (INTEGER if all elements are integers). |
| `type_of(v)` | all | Returns the object type name of v (e.g. INTEGER, STRING, ARRAY). |
| `unique(array)` | all | Returns a new array with duplicate values removed (order preserved). |
| `values(hash)` | all | Returns the hash values as an array (ordered by sorted key). |
| `zip(a, b)` | all | Returns an array of [a[i], b[i]] pairs up to the shorter length. |

## Strings (18)

Rune-aware string manipulation: case, trimming, padding, slicing, joining, and formatting. Pairs with the `text_*`/`regex_*` matching family.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `str_char_at(s, index)` | all | Returns the rune at index as a string. |
| `str_ends_with(s, suffix)` | all | Returns whether s ends with suffix. |
| `str_format(format, ...values)` | all | Returns a printf-style formatted string (like putf but returns instead of printing). |
| `str_join(array, sep)` | all | Joins an array of strings with sep (inverse of text_split). |
| `str_lower(s)` | all | Returns s with all letters lower-cased. |
| `str_pad_left(s, width, pad)` | all | Left-pads s with pad until it reaches width runes. |
| `str_pad_right(s, width, pad)` | all | Right-pads s with pad until it reaches width runes. |
| `str_repeat(s, n)` | all | Returns s repeated n times. |
| `str_reverse(s)` | all | Returns s reversed (rune-aware). |
| `str_starts_with(s, prefix)` | all | Returns whether s begins with prefix. |
| `str_substr(s, start, length)` | all | Returns length runes of s starting at rune index start (clamped to bounds). |
| `str_title(s)` | all | Upper-cases the first letter of each word in s. |
| `str_trim(s)` | all | Returns s with leading and trailing whitespace removed. |
| `str_trim_left(s, cutset)` | all | Trims any leading characters in cutset from s. |
| `str_trim_prefix(s, prefix)` | all | Removes prefix from s if present. |
| `str_trim_right(s, cutset)` | all | Trims any trailing characters in cutset from s. |
| `str_trim_suffix(s, suffix)` | all | Removes suffix from s if present. |
| `str_upper(s)` | all | Returns s with all letters upper-cased. |

## Text Analysis (14)

Substring search, splitting/replacing, regular expressions, and fuzzy matching (Levenshtein, Jaro-Winkler, similarity).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `regex_capture_groups(pattern, input)` | all | Returns full regex capture array (full match plus groups). |
| `regex_find(pattern, input)` | all | Finds the first regex match in input. |
| `regex_find_all(pattern, input, limit?)` | all | Finds all regex matches with optional result limit. |
| `regex_match(pattern, input)` | all | Returns whether regex pattern matches input. |
| `regex_replace(pattern, input, replacement)` | all | Replaces all regex matches in input with replacement text. |
| `text_contains(haystack, needle)` | all | Returns whether a string contains a substring. |
| `text_count(haystack, needle)` | all | Counts non-overlapping substring occurrences. |
| `text_fuzzy_find(query, candidates, maxDistance?)` | all | Finds the closest fuzzy match in an array of candidate strings. |
| `text_index(haystack, needle)` | all | Returns the first index of substring occurrence, or -1. |
| `text_jaro_winkler(left, right)` | all | Computes Jaro-Winkler string similarity score. |
| `text_levenshtein(left, right)` | all | Computes Levenshtein edit distance between two strings. |
| `text_replace(text, old, new)` | all | Replaces substring occurrences in text. |
| `text_similarity(left, right)` | all | Computes normalized Levenshtein similarity between two strings. |
| `text_split(text, sep)` | all | Splits text by separator and returns an array of parts. |

## Structured Data (25)

JSON parse/serialize for nested objects, base64/base32/hex/URL encoding, gzip/zlib compression, base conversion, and type conversion. See [STRUCTURED_DATA.md](STRUCTURED_DATA.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `base32_decode(s)` | all | Decodes standard base32; returns (bytes, err). |
| `base32_encode(s)` | all | Standard base32-encodes s. |
| `base64_decode(s)` | all | Decodes standard base64; returns (bytes, err). |
| `base64_encode(s)` | all | Standard base64-encodes s. |
| `base64url_decode(s)` | all | Decodes URL-safe base64; returns (bytes, err). |
| `base64url_encode(s)` | all | URL-safe base64-encodes s. |
| `from_base(s, base)` | all | Parses s as an integer in the given base (2–36); returns (int, err). |
| `gunzip(s)` | all | Gzip-decompresses s; returns (bytes, err). |
| `gzip(s)` | all | Gzip-compresses s (returns a byte string). |
| `hex_decode(s)` | all | Decodes a hex string to bytes; returns (bytes, err). |
| `hex_encode(s)` | all | Hex-encodes a byte string to lowercase hex. |
| `json_parse(text)` | all | Parses JSON text into Mutant values. |
| `json_stringify(value)` | all | Serializes Mutant values into JSON text. |
| `parse_float(s)` | all | Parses s as a float; returns (float, err). |
| `parse_int(s, base)` | all | Parses s as an integer in base (0 auto-detects); returns (int, err). |
| `plist_parse(path)` | all | Parses an Apple property list (binary bplist00 or XML) into a Mutant value: dict->hash, array->array, string/integer/real/bool as scalars; dates and data become strings. Returns (value, err). |
| `to_base(n, base)` | all | Formats integer n in the given base (2–36). |
| `to_bool(v)` | all | Converts a bool/number/string to BOOLEAN; returns (bool, err). |
| `to_float(v)` | all | Converts a number/bool/string to FLOAT; returns (float, err). |
| `to_int(v)` | all | Converts a number/bool/string to INTEGER; returns (int, err). |
| `to_string(v)` | all | Converts any value to its STRING representation. |
| `url_decode(s)` | all | URL query-unescapes s; returns (value, err). |
| `url_encode(s)` | all | URL query-escapes s. |
| `zlib_compress(s)` | all | Zlib-compresses s (returns a byte string). |
| `zlib_decompress(s)` | all | Zlib-decompresses s; returns (bytes, err). |

## Math (5)

Numeric constants and random-number helpers (cryptographically-random bytes via `rand_bytes`). Arithmetic helpers like `abs`/`min`/`max`/`sum` live in the standard library.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `math_e()` | all | Returns the constant e. |
| `math_pi()` | all | Returns the constant pi. |
| `rand()` | all | Returns a random FLOAT in [0, 1). |
| `rand_bytes(n)` | all | Returns n cryptographically-random bytes (as a byte string). |
| `rand_int(lo, hi)` | all | Returns a random INTEGER in [lo, hi). |

## Hashing (11)

Cryptographic and checksum digests (MD5/SHA-1/SHA-256/SHA-512/CRC-32/BLAKE2), HMAC, and identifier generators (UUID v4/v7, nanoid, random hex).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `hash_blake2(s)` | all | Returns the lowercase hex BLAKE2b-256 digest of s. |
| `hash_crc32(s)` | all | Returns the CRC-32 (IEEE) checksum of s as 8 hex chars. |
| `hash_md5(s)` | all | Returns the lowercase hex MD5 digest of s. |
| `hash_sha1(s)` | all | Returns the lowercase hex SHA-1 digest of s. |
| `hash_sha256(s)` | all | Returns the lowercase hex SHA-256 digest of s. |
| `hash_sha512(s)` | all | Returns the lowercase hex SHA-512 digest of s. |
| `hmac(key, message, algo)` | all | Returns the hex HMAC of message under key. algo is md5/sha1/sha256/sha512. |
| `nanoid(n)` | all | Returns a URL-safe random identifier of length n. |
| `random_hex(n)` | all | Returns n cryptographically-random bytes as a 2n-char hex string. |
| `uuid_v4()` | all | Returns a random (v4) UUID string. |
| `uuid_v7()` | all | Returns a time-ordered (v7) UUID string. |

## Time (7)

Unix timestamps, formatting, parsing, and arithmetic (UTC).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `time_add(unix, seconds)` | all | Returns the Unix timestamp shifted by seconds. |
| `time_diff(a, b)` | all | Returns a - b in seconds (both Unix timestamps). |
| `time_format(unix, layout)` | all | Formats a Unix timestamp (UTC) using a Go reference layout. |
| `time_ms()` | all | Returns the current Unix time in milliseconds. |
| `time_now()` | all | Returns the current UTC time as a hash {unix, iso, year, month, day, hour, minute, second}. |
| `time_parse(value, layout)` | all | Parses value with a Go reference layout; returns (unixSeconds, err). |
| `time_unix()` | all | Returns the current Unix time in seconds. |

## Bytes (30)

Binary buffer inspection and construction: fixed-width integer reads/writes (LE/BE), a streaming cursor, slicing, and byte/char conversions.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bytes_char_from_int(value)` | all | Converts an integer byte value to a single-character string. |
| `bytes_cstr_at(data, offset)` | all | Reads null-terminated string from bytes at offset. |
| `bytes_cursor_eof(cursor)` | all | Returns whether cursor is at end-of-buffer. |
| `bytes_cursor_new(data)` | all | Creates a cursor for structured byte parsing. |
| `bytes_cursor_read_u16_be(cursor)` | all | Reads unsigned 16-bit big-endian integer from cursor. |
| `bytes_cursor_read_u16_le(cursor)` | all | Reads unsigned 16-bit little-endian integer from cursor. |
| `bytes_cursor_read_u32_be(cursor)` | all | Reads unsigned 32-bit big-endian integer from cursor. |
| `bytes_cursor_read_u32_le(cursor)` | all | Reads unsigned 32-bit little-endian integer from cursor. |
| `bytes_cursor_read_u64_be(cursor)` | all | Reads unsigned 64-bit big-endian integer from cursor. |
| `bytes_cursor_read_u64_le(cursor)` | all | Reads unsigned 64-bit little-endian integer from cursor. |
| `bytes_cursor_read_u8(cursor)` | all | Reads one unsigned byte from cursor. |
| `bytes_cursor_seek(cursor, offset)` | all | Moves cursor to an absolute offset. |
| `bytes_cursor_tell(cursor)` | all | Returns current cursor position. |
| `bytes_get(data, index)` | all | Reads one byte at index as integer. |
| `bytes_hex(value, width)` | all | Formats an integer as a zero-padded uppercase hex string with a 0x prefix (e.g. bytes_hex(4660, 8) -> "0x00001234"). This formats a number; it does not hex-encode a byte string. |
| `bytes_int_from_char(char)` | all | Converts a single-character string to its integer byte value. |
| `bytes_len(data)` | all | Returns length of a bytes value. |
| `bytes_read_u16_be(data, offset)` | all | Reads unsigned 16-bit big-endian integer from bytes at offset. |
| `bytes_read_u16_le(data, offset)` | all | Reads unsigned 16-bit little-endian integer from bytes at offset. |
| `bytes_read_u32_be(data, offset)` | all | Reads unsigned 32-bit big-endian integer from bytes at offset. |
| `bytes_read_u32_le(data, offset)` | all | Reads unsigned 32-bit little-endian integer from bytes at offset. |
| `bytes_read_u64_be(data, offset)` | all | Reads unsigned 64-bit big-endian integer from bytes at offset. |
| `bytes_read_u64_le(data, offset)` | all | Reads unsigned 64-bit little-endian integer from bytes at offset. |
| `bytes_slice(data, start, length)` | all | Returns a byte sub-slice of the given length starting at start (i.e. data[start:start+length]). |
| `bytes_write_u16_be(data, offset, value)` | all | Writes unsigned 16-bit big-endian integer into bytes at offset. |
| `bytes_write_u16_le(data, offset, value)` | all | Writes unsigned 16-bit little-endian integer into bytes at offset. |
| `bytes_write_u32_be(data, offset, value)` | all | Writes unsigned 32-bit big-endian integer into bytes at offset. |
| `bytes_write_u32_le(data, offset, value)` | all | Writes unsigned 32-bit little-endian integer into bytes at offset. |
| `bytes_write_u64_be(data, offset, value)` | all | Writes unsigned 64-bit big-endian integer into bytes at offset. |
| `bytes_write_u64_le(data, offset, value)` | all | Writes unsigned 64-bit little-endian integer into bytes at offset. |

## Filesystem (19)

Read/write/manage files and directories, plus file-level forensics: hashing, entropy, string extraction, magic-type detection, carving, diffing, and NTFS deleted-file recovery.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `fs_append(path, data)` | all | Appends data to the end of a file. |
| `fs_carve(path, type)` | all | Scans a file for a known artifact signature and returns the byte offsets where it starts. It reports offsets only; it does not extract (carve out) the artifact bytes or determine their length. |
| `fs_copy(src, dst)` | all | Copies a file from source path to destination path. |
| `fs_delete(path)` | all | Deletes a file from disk. |
| `fs_deleted(path)` | all | Enumerates deleted files from an NTFS $MFT (a standalone $MFT file or a full volume image, auto-detected). A record is deleted when its in-use flag is clear but its metadata still parses. Small files with a resident $DATA attribute are fully recovered (resident_data, hex-encoded); larger non-resident files report metadata only. Returns {source_type, deleted_count, skipped, entries:[{record, name, path, size, is_directory, has_data, resident, recoverable, resident_data, si_*, fn_*}]}. Returns (result, err). |
| `fs_diff(leftPath, rightPath)` | all | Compares two files (not directories) and reports differences. |
| `fs_entropy(path)` | all | Computes file entropy for packed/encrypted artifact detection. |
| `fs_exists(path)` | all | Returns whether a file or directory exists. |
| `fs_extract_strings(path, minLen?)` | all | Extracts printable strings from a file. |
| `fs_hash(path)` | all | Computes hash digests for a file. |
| `fs_list(path)` | all | Lists directory entries for a path. |
| `fs_magic(path)` | all | Infers file type/magic from a file's header against a ~40-signature database (executables PE/ELF/Mach-O, images, archives, documents, SQLite/registry/EVTX/pcap, media, and forensic artifacts like lnk/prefetch). Returns {path, type, mime, signature}. |
| `fs_metadata(path)` | all | Returns detailed filesystem metadata for a path. |
| `fs_mkdir(path)` | all | Creates a directory path. |
| `fs_move(src, dst)` | all | Moves or renames a file or directory. |
| `fs_read(path)` | all | Reads file contents from disk. |
| `fs_stat(path)` | all | Returns file metadata such as size and timestamps. |
| `fs_walk(root)` | all | Walks a directory tree and returns discovered paths. |
| `fs_write(path, data)` | all | Writes data to a file, replacing existing contents. |

## Network (32)

Sockets and TLS sessions, an in-process X.509 CA, HTTP-message inspection, listeners/serve loops, WebSocket framing, scanning, and offline pcap analysis. See [SECURE_NETWORKING.md](SECURE_NETWORKING.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `net_accept(listener, timeoutMs)` | all | Accepts one connection; returns {ok, handle, remote_addr, timeout, error}. |
| `net_banner(address, timeoutMs)` | all | Collects service banner text from a network endpoint. |
| `net_capture_raw(pcap_path)` | all | Reads raw packets from an offline pcap file into a per-packet listing (live interface capture needs cgo/raw sockets and is unavailable; net_pcap_analyze gives the flow summary, this gives the packets). Returns {file, link_type, count, truncated, packets:[{index, ts, timestamp, length, src, dst, protocol, sport, dport}]}. Returns (result, err). |
| `net_conn_close(handle)` | all | Closes a connection and releases its handle. |
| `net_conn_info(handle)` | all | Returns addressing and negotiated TLS session details for a connection. |
| `net_conn_read(handle, maxBytes, timeoutMs)` | all | Reads up to maxBytes from a connection; returns {data, bytes, eof, error} with I/O failures in the error field. |
| `net_conn_write(handle, data, timeout_ms?)` | all | Writes bytes to a connection and returns the number written. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write. |
| `net_connect(address, timeoutMs)` | all | Opens a persistent TCP connection and returns a connection handle. |
| `net_connect_scan(host, startPort, endPort, timeoutMs)` | all | Scans a TCP port range on a host using full connect() probes (net.Dial). Pure-Go and unprivileged; not a half-open SYN scan (which needs raw sockets/privileges). |
| `net_dial(address, timeoutMs)` | all | Connectivity probe: dials address, immediately closes, and returns {ok, latency_ms, error}. Does not return a usable connection (use net_connect for that). |
| `net_dns_query(name, qtype)` | all | Queries DNS records for a hostname. |
| `net_flow_reconstruct(packets)` | all | Reconstructs higher-level flows from packet records. |
| `net_listen(address)` | all | Opens a plain TCP listener and returns a listener handle. |
| `net_listen_close(handle)` | all | Closes a listener and releases its handle. |
| `net_os_fingerprint(pcap_path)` | all | Passively fingerprints OS families from TCP SYN/SYN-ACK packets in an offline pcap (p0f-style heuristic over TTL, DF, window, and TCP options). Identifies an OS family, not a definitive OS; runs offline with no privileges. |
| `net_pcap_analyze(path)` | all | Analyzes PCAP captures and returns flow/session signals. |
| `net_resolve(host)` | all | Resolves a host name to network addresses. |
| `net_serve(listener, handler_path, arg?)` | all | Accept loop that dispatches each connection to a fresh VM running handler_path; handler reads its connection via serve_conn() and shared arg via serve_arg(). Concurrent. |
| `net_spawn(handler_path, arg?)` | all | Runs handler_path on a new goroutine with no connection (serve_conn()->0) and arg via serve_arg(). For auxiliary workers, e.g. a WebSocket reverse pump. |
| `net_syn_scan(host, startPort, endPort, timeoutMs)` | all | DEPRECATED alias of net_connect_scan. This is a full TCP connect scan, not a half-open SYN scan; use net_connect_scan. |
| `net_tls_connect(address, timeoutMs, options?)` | all | Opens a TLS (secure) client connection and returns a connection handle. |
| `net_tls_fingerprint(address, timeoutMs)` | all | Collects TLS certificate and handshake fingerprint metadata. |
| `net_tls_listen(address, certPem, keyPem, options?)` | all | Opens a TLS-terminating listener from a PEM cert/key pair. |
| `net_tls_upgrade_client(handle, options?)` | all | Upgrades an open connection to client-side TLS (STARTTLS / upstream leg). |
| `net_tls_upgrade_server(handle, certPem, keyPem, options?)` | all | Upgrades an accepted connection to server-side TLS (completes a CONNECT intercept). |
| `net_udp_scan(host, startPort, endPort, timeoutMs)` | all | Scans a UDP port range on a host. |
| `tls_generate_ca(options?)` | all | Creates a self-signed CA certificate and key; returns {cert_pem, key_pem, serial}. |
| `tls_generate_cert(options?)` | all | Creates a self-signed leaf/server certificate and key. |
| `tls_sign_cert(caCertPem, caKeyPem, options?)` | all | Issues a leaf certificate signed by a CA (per-host interception cert). |
| `ws_accept_key(client_key)` | all | Computes the Sec-WebSocket-Accept value for an RFC 6455 101 handshake response. |
| `ws_read_frame(handle, timeoutMs)` | all | Reads one WebSocket frame (unmasked); returns {fin, opcode, payload, masked, length, is_control}. |
| `ws_write_frame(handle, opcode, payload, mask, timeout_ms?)` | all | Writes one WebSocket frame; mask=true for client->server, false for server->client. A write deadline (default 30s, or timeout_ms; <=0 blocks forever) prevents a stalled peer from hanging the write. |

## Http (11)

HTTP client requests and low-level request/response parsing and building for proxy/inspection workflows.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `http_build_request(request)` | all | Serialises a request hash into HTTP wire bytes. |
| `http_build_response(response)` | all | Serialises a response hash into HTTP wire bytes (adds Content-Length). |
| `http_conn_read_request(handle, timeoutMs)` | all | Reads exactly one HTTP request from a connection handle. |
| `http_conn_read_request_head(handle, timeoutMs)` | all | Reads a request's line+headers without the body (stream it via net_conn_read); adds content_length, chunked. |
| `http_conn_read_response(handle, timeoutMs)` | all | Reads exactly one HTTP response from a connection handle. |
| `http_conn_read_response_head(handle, timeoutMs)` | all | Reads a response's status line+headers without the body (stream it via net_conn_read); adds content_length, chunked. |
| `http_get(url)` | all | Performs an HTTP GET request. |
| `http_parse_request(raw)` | all | Parses a raw HTTP request into {method, url, path, host, proto, query, headers, body}. |
| `http_parse_response(raw)` | all | Parses a raw HTTP response into {status, status_text, proto, headers, body}. |
| `http_post(url, body, contentType?)` | all | Performs an HTTP POST request. contentType defaults to application/octet-stream when omitted. |
| `http_request(method, url, body, headers)` | all | Performs an HTTP request with a body and a headers hash. All four arguments are required; the timeout is a fixed 30s (not configurable). |

## Graph Database (14)

Graph-oriented data modeling: typed nodes/edges, named relations, indexed artifact attributes, BFS traversal, shortest-path, statistics, and timelines. See [GRAPH_DATABASE.md](GRAPH_DATABASE.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `db_add_artifact(db, type, attrs?)` | all | Adds a forensic artifact node. type is a STRING; attrs is an optional properties hash that is indexed. |
| `db_add_edge(db, from, to, edgeType?)` | all | Adds an edge between two node IDs. edgeType is an optional integer/enum edge type. Edge property hashes are not supported. |
| `db_add_node(db, nodeType?)` | all | Adds a DATA node and returns its ID. nodeType is an optional integer/enum node type (0–127; 0 is the DATA type used when omitted). Property hashes are not supported. |
| `db_add_relation(db, from, to, relation)` | all | Adds a named relation edge between two entity IDs. All four arguments are required; property hashes are not supported. |
| `db_bfs(db, origin, depth, direction)` | all | Breadth-first traversal from origin up to depth. direction is "in", "out", or "both". All four arguments are required. |
| `db_close(db)` | all | Closes a graph database handle and flushes pending state. |
| `db_index_prop(db, nodeID, key, value)` | all | Indexes a property (key=value) on a node. All four arguments are required. |
| `db_open()` | all | Creates an in-memory graph database handle. |
| `db_open_disk(path)` | all | Opens or creates a disk-backed graph database. Note that compacting a store with this build rewrites it in a newer on-disk format that older mutant builds cannot open. |
| `db_query(db)` | all | Returns all DATA-type node IDs (an alias for db_query_nodes with no type filter). There is no query-expression language. |
| `db_query_nodes(db, nodeType?)` | all | Returns node IDs, optionally filtered to a single node type (integer/enum). |
| `db_shortest_path(db, from, to)` | all | Computes shortest path between two graph nodes. |
| `db_stats(db)` | all | Returns graph database statistics: {nodes, edges, has_storage}. Disk-backed handles also report delta_records, csr_records, deleted_nodes, deleted_edges, wal_bytes, commit_seq and last_compact — growing delta_records/wal_bytes means the store is overdue for compaction. |
| `db_timeline(db)` | all | Returns chronological timeline events recorded in the graph. Takes only the handle (no options argument). |

## Cache (8)

In-memory key/value cache with TTLs and hit/miss statistics.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cache_clear(name)` | all | Clears all entries and resets relevant cache state. |
| `cache_close(name)` | all | Closes a named cache and frees its entries and backend. |
| `cache_delete(name, key)` | all | Deletes a key from cache and returns whether it existed. |
| `cache_get(name, key)` | all | Reads a value from cache and returns found/value fields. |
| `cache_keys(name)` | all | Lists sorted cache keys for a cache namespace. |
| `cache_open(name)` | all | Opens or creates a named in-memory cache store. |
| `cache_put(name, key, value, ttlSeconds?)` | all | Stores a value in a named cache key with optional TTL. |
| `cache_stats(name)` | all | Returns cache counters such as hits, misses, puts, deletes, and expires. |

## Policy (5)

Load and evaluate allow/deny policies with rule metadata and evaluation traces.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `policy_allow(policy, input)` | all | Evaluates and returns allow/deny boolean for a policy. |
| `policy_eval(policy, input)` | all | Evaluates a loaded policy and returns decision details. |
| `policy_load(name, source)` | all | Loads a policy module by name from source text or config hash. |
| `policy_rules(policy)` | all | Returns rule metadata exported by a loaded policy. |
| `policy_trace(policy, input)` | all | Runs policy evaluation with trace output for debugging rule flow. |

## Runtime Integration (3)

Embed and securely execute Lua in a restricted sandbox (no `io`, dangerous `os.*` stripped, bounded execution). See [RUNTIME_INTEGRATION.md](RUNTIME_INTEGRATION.md).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `lua_run_file(path)` | all | Runs a Lua script from a file. |
| `lua_run_http(url)` | all | Fetches and runs a Lua script from an HTTP endpoint in a restricted sandbox (no io, no os.execute/exit/remove; only safe base/math/string/table/os-time libraries). |
| `lua_run_string(code)` | all | Runs a Lua script from a string. |

## Command Execution (4)

Guarded execution of external commands, subject to the `command_exec` capability policy.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cmd_add(builder, arg)` | all | Appends an argument to a command builder. |
| `cmd_builder(shell?)` | all | Creates a command builder object for step-wise command composition. |
| `cmd_run(builder)` | all | Executes a composed command and returns run output metadata. |
| `exec_string(command, shell?)` | all | Executes a shell command string via security-guarded command execution. |

## Cryptography (5)

X.509 certificate parsing, JWT decoding, PEM decoding, and authenticated AES-GCM encryption/decryption.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `aes_decrypt(key, ciphertext)` | all | AES-GCM decrypts ciphertext produced by aes_encrypt (nonce-prefixed). Returns (plaintext, err); errors on wrong key or tampering. |
| `aes_encrypt(key, plaintext)` | all | AES-GCM encrypts plaintext. key must be 16/24/32 bytes. A random nonce is prepended to the output. Returns (ciphertext, err). |
| `jwt_decode(token)` | all | Decodes a JWT's header and claims WITHOUT verifying the signature (verified is always false). Returns {header, claims, algorithm, signature_present, verified}. Returns (result, err). |
| `pem_decode(s)` | all | Decodes the first PEM block. Returns {type, headers, der_hex, size, remaining_bytes}. Returns (result, err). |
| `x509_parse(pem_or_der)` | all | Parses an X.509 certificate (PEM or DER). Returns {subject, issuer, serial, not_before, not_after, is_ca, version, dns_names, ip_addresses, email_addresses, key_algorithm, signature_algorithm, sha1, sha256}. Returns (cert, err). |

## Fingerprinting (4)

Malware/host fingerprints: PE import hash (imphash), JA3 TLS-client fingerprint, and NTLM/LM password hashes (for authorized credential testing).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `imphash(pe_path)` | all | Computes the PE import hash (pefile/Mandiant algorithm) for malware clustering. Returns {imphash, import_count, dll_count}. Note: ordinal-only imports are rendered as ord<N>, so results may differ from VT for ws2_32/oleaut32 ordinal imports. Returns (result, err). |
| `ja3(client_hello)` | all | Computes the JA3 TLS-client fingerprint from a ClientHello (raw bytes, with or without the TLS record layer). Hashes version,ciphers,extensions,curves,point_formats with GREASE (RFC 8701) removed. Returns {ja3, ja3_hash (md5), tls_version, ciphers[], extensions[], curves[], point_formats[]}. Returns (result, err). |
| `lm_hash(password)` | all | Returns the legacy LM hash (DES-based; case-insensitive, max 14 chars) as hex. Empty password -> aad3b435b51404eeaad3b435b51404ee. |
| `nt_hash(password)` | all | Returns the NTLM NT hash (MD4 of the UTF-16LE password) as hex. For authorized credential testing/CTF use. |

## Network Intelligence (11)

IOC handling: defang/refang, IP/CIDR math, domain/eTLD+1 extraction, validation, and IOC extraction from free text.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `cidr_hosts(cidr)` | all | Returns all addresses in a CIDR range (capped; errors if >20 host bits). |
| `defang(ioc)` | all | Defangs an indicator for safe display (http->hxxp, .->[.], @->[at]). |
| `domain_extract(url)` | all | Extracts the lowercased hostname from a URL or host string. |
| `extract_iocs(text)` | all | Extracts IOCs from text (refanged first): {ipv4, urls, domains, emails, md5, sha1, sha256}, each unique and sorted. |
| `ip_in_cidr(ip, cidr)` | all | Returns whether an IP falls within a CIDR range. |
| `ip_is_private(ip)` | all | Returns whether an IP is private/loopback/link-local (RFC1918 etc.). |
| `ip_to_int(ip)` | all | Converts an IPv4 address to its 32-bit integer form. |
| `ip_version(ip)` | all | Returns 4, 6, or 0 (invalid) for an IP address. |
| `is_valid_domain(s)` | all | Returns whether s is a syntactically valid domain name. |
| `refang(ioc)` | all | Reverses common defang encodings ([.]/(.)/[dot]->., hxxp->http, [at]->@). |
| `tld_extract(domain)` | all | Returns {domain, etld1, suffix} using the public suffix list. |

## Detection (5)

Heuristic detectors for code injection, C2 beaconing, persistence, privilege escalation, and suspicious files, driven by supplied evidence.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `detect_injection(facts)` | all | Scores probable code injection in a memory image using multiple PE headers plus weighted shellcode signatures (GetPC via fnstenv/call-pop, PEB walks, NOP sleds); returns score and matched_signatures. |
| `detect_network_beacon(flows)` | all | Detects C2 beaconing by analyzing inter-arrival interval regularity (low coefficient of variation) and optional transfer-size consistency per destination; each flow may carry ts (epoch/RFC3339) and bytes. Returns per-dst score, interval_cv, and confidence. |
| `detect_persistence(facts)` | all | Detects persistence indicators from host evidence facts. |
| `detect_priv_esc(facts)` | all | Detects potential privilege-escalation indicators from host facts. |
| `detect_suspicious_files(paths)` | all | Flags suspicious files via entropy tiers (high/very-high), executable magic under a document extension (extension_mismatch), and disguised double extensions (e.g. invoice.pdf.exe). |

## Process Forensics (9)

Live process inspection: enumeration, tree, environment, open files, threads, modules, executable hashing, memory scanning, and signaling.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `process_env(pid?)` | all | Returns environment variables for a process (cross-platform; other processes may require privileges). |
| `process_hash(pid?)` | all | Computes SHA-256 hash metadata for a process executable. |
| `process_kill(pid, signal?)` | all | Sends a signal to a process (default SIGKILL semantics). (On Windows only SIGKILL semantics are honored; other signal numbers are ignored.) |
| `process_list()` | all | Lists running processes (pid, ppid, name) natively on Windows, Linux, and macOS. |
| `process_memory_scan(pid, pattern)` | windows, linux | Scans a process's readable memory for a byte pattern and returns {pid, pattern, matched, truncated, addresses}. Real scan on Linux (/proc/self/mem) and Windows (VirtualQuery+ReadProcessMemory); self process only for now; honest error on macOS. |
| `process_modules(pid?)` | windows, linux | Lists loaded module/library paths for a process (memory maps on Linux, Toolhelp32 on Windows; fails honestly on platforms without a backend, e.g. macOS). |
| `process_open_files(pid?)` | all | Lists open file paths for a process (cross-platform; may require privileges for other processes). |
| `process_threads(pid?)` | all | Returns {pid, count, tids} for a process. The thread count is cross-platform; tids are populated where the OS exposes them (e.g. Linux). |
| `process_tree(rootPid?)` | all | Returns descendant processes for a root pid (default current process). Cross-platform, using real parent PIDs on every OS. |

## Memory Forensics (6)

Memory-dump analysis: segmentation with entropy, string extraction, pattern scanning, and PE/shellcode discovery.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `mem_find_pe(path)` | all | Finds PE headers in a memory image: carves each MZ marker and confirms real PEs by following e_lfanew to "PE\0\0". Returns {candidates, confirmed, headers:[{mz_offset, confirmed, pe_offset, machine}]}. |
| `mem_find_shellcode(path)` | all | Scans a memory dump file for common shellcode byte signatures. |
| `mem_map(path)` | all | Splits a memory dump into fixed-size (4 KiB) segments, each with measured entropy and printable-byte ratio. A raw dump carries no page-protection metadata, so no readable/writable/executable flags are reported. |
| `mem_read(path, offset, size)` | all | Reads a byte range from a memory image. |
| `mem_scan(path, pattern)` | all | Scans a memory image for a string/byte pattern. |
| `mem_strings(path, minLen?)` | all | Extracts printable strings from memory image data. |

## Binary Analysis (14)

PE/ELF/Mach-O/DWARF parsing, imports, sections, strings, entropy, literal signature scanning, and Go-binary metadata recovery (GoReSym).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bin_dwarf_parse(path)` | all | Parses DWARF metadata and reports compile unit information. |
| `bin_elf_parse(path)` | all | Parses ELF headers and returns core binary metadata. |
| `bin_entropy(path)` | all | Computes binary entropy signal. |
| `bin_imports(path)` | all | Returns imported symbols/libraries from a binary. |
| `bin_is_go(path)` | all | Quick check whether a binary was produced by the Go toolchain, using three signals (build info blob, Go build ID, and a parseable pclntab — the one that survives stripping). Returns {is_go, go_version, has_buildinfo, has_build_id, has_pclntab}. Returns (result, err). |
| `bin_macho_parse(path)` | all | Parses a Mach-O binary (macOS/iOS). Handles thin and fat/universal images. For a thin binary returns {format, fat, magic, cpu, type, flags, num_sections, num_commands, imported_libraries}; for a fat binary returns {format, fat, num_arches, architectures:[{cpu, type, offset, size, align}]}. Returns (result, err). |
| `bin_pe_parse(path)` | all | Parses PE headers and returns core binary metadata. |
| `bin_sections(path)` | all | Returns binary section table information. |
| `bin_strings(path, minLen?)` | all | Extracts printable strings from a binary. |
| `bin_yara_scan(path, rules, caseInsensitive?)` | all | Literal multi-string scan of a file (NOT a real YARA engine — that needs cgo). Reports every offset of each rule string. Case-sensitive unless caseInsensitive is true. Returns {engine, matched, total_hits, hits:[{rule, count, offsets}]}. |
| `go_build_id(path)` | all | Extracts the Go build ID from a binary. Returns (build_id, err). |
| `go_buildinfo(path)` | all | Extracts Go build info from a binary: go_version, module path, main module, dependencies (path/version/sum), and build settings (GOOS/GOARCH/vcs.*). Returns (info, err). |
| `go_symbols(path, mode?)` | all | Recovers function symbols from a Go binary via the pclntab — works even on STRIPPED binaries. Returns {go_version, arch, os, pclntab_va, function_count, user_function_count, std_function_count, functions:[{name, package, start, end, stdlib}]}. mode is "all" (default), "user", or "std". Returns (result, err). |
| `go_types(path)` | all | Recovers type and interface definitions from a Go binary via GoReSym typelink/itablink parsing, including reconstructed Go source for structs/interfaces where possible. Returns {go_version, type_count, itab_count, types:[{va, name, kind, reconstructed}], itabs:[...]}. Type recovery needs a parseable moduledata; GoReSym v1.7.1 supports it up to ~Go 1.24 and returns an honest error on newer toolchains. Returns (result, err). |

## Registry Forensics (15)

Windows registry across three sources via one polymorphic API (regf hive file, hive-JSON, or live Windows registry), plus Amcache and Shimcache execution evidence.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `amcache_parse(path)` | all | Parses an Amcache.hve hive (program execution/presence evidence) into {format, count, entries:[{key, path, name, sha1, publisher, version, product, size, last_write}]}. Supports the modern InventoryApplicationFile and legacy Root\File layouts. Returns (result, err). |
| `hive_close(handle)` | all | Closes a hive handle. Returns (bool, err). |
| `hive_get_value(handle, keypath, name)` | all | Returns {name, type, data} for a single value under keypath. Returns (result, err). |
| `hive_key_info(handle, keypath?)` | all | Returns {name, last_write, last_write_iso, subkey_count, value_count} for a key (keypath is backslash-separated under the root; default root). Returns (result, err). |
| `hive_list_keys(handle, keypath?)` | all | Returns the subkey names under a key (default root) as an array. Returns (array, err). |
| `hive_list_values(handle, keypath?)` | all | Returns a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Returns (array, err). |
| `hive_open(path)` | all | Opens a real Windows registry hive (regf binary format — SOFTWARE/SYSTEM/NTUSER.DAT, etc.) and returns {handle, path}. Distinct from the JSON-fixture reg_* family. Returns (result, err). |
| `reg_close(handle)` | all | Closes a registry-hive handle opened with reg_open. |
| `reg_deleted_keys(handle)` | all | Lists deleted-key entries. Populated only for the JSON source (its deleted_keys field); empty for real hive files and live registry (no unallocated-cell carving). |
| `reg_enum_keys(handle, keyPath?)` | all | Enumerates subkeys under a key. For hive/live sources keyPath is relative to the opened key (default root); for JSON it is the absolute path. Returns (array, err). |
| `reg_enum_values(handle, keyPath?)` | all | Enumerates a key's values as [{name, type, data}] (REG_SZ/DWORD/QWORD/MULTI_SZ decoded; binary as hex). Works across JSON/hive-file/live sources. Returns (array, err). |
| `reg_get_value(handle, keyPath, valueName)` | all | Reads a specific registry value with type metadata, across JSON/hive-file/live sources. Returns (result, err). |
| `reg_open(source)` | all | Opens a registry data source (polymorphic) and returns {handle, path, source_type, status}. Dispatch: a regf hive file (SOFTWARE/SYSTEM/NTUSER.DAT, …) -> real hive parse; a hive-JSON file -> JSON; otherwise a live Windows registry path (e.g. HKLM\SOFTWARE\...) -> live registry (Windows only). Returns (result, err). (The live-registry path (HKLM\..., HKCU\..., etc.) is Windows-only; captured hive files and hive-JSON inputs are parsed on all platforms.) |
| `reg_timeline(handle)` | all | Returns timeline entries. Populated only for the JSON source (its timeline field); empty for real hive files and live registry. |
| `shimcache_parse(path)` | all | Decodes the Windows AppCompatCache (shimcache) — program execution/presence evidence. Accepts a SYSTEM hive file (locates the value) or a raw AppCompatCache blob. Supports Win8/Win8.1/Win10 (10ts/00ts). Returns {version, count, entries:[{position, path, last_modified, last_modified_iso}]}. Returns (result, err). |

## Filesystem Forensics (31)

Read-only filesystem parsers for NTFS/FAT/exFAT/ext/HFS+/XFS images and standalone $MFT timelines, with rich MAC timestamps and metadata.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `ext_close(handle)` | all | Closes an ext handle and releases its file. |
| `ext_list_files(handle, dir)` | all | Lists entries under a directory in an opened ext image, with created_at/modified_at/accessed_at/changed_at and deleted. |
| `ext_metadata(handle, path)` | all | Returns metadata for a path in an opened ext image, including created_at/modified_at/accessed_at/changed_at, deleted, and warnings (where the parser judged the answer may be incomplete). |
| `ext_open(image)` | all | Opens an ext2/3/4 filesystem image and returns a handle. Returns (result, err). |
| `ext_read_file(handle, path)` | all | Reads a file's bytes from an opened ext image. |
| `fat_close(handle)` | all | Closes a FAT handle and releases its file. |
| `fat_list_files(handle, dir)` | all | Lists entries under a directory in an opened FAT image. |
| `fat_metadata(handle, path)` | all | Returns metadata for a path in an opened FAT image. |
| `fat_open(image)` | all | Opens a FAT filesystem image and returns a handle. Returns (result, err). |
| `fat_read_file(handle, path)` | all | Reads a file's bytes from an opened FAT image. |
| `hfs_close(handle)` | all | Closes an HFS+ handle and releases its file. |
| `hfs_list_files(handle, dir)` | all | Lists entries under a directory in an opened HFS+ image. |
| `hfs_metadata(handle, path)` | all | Returns metadata for a path in an opened HFS+ image, including created_at/modified_at/accessed_at/changed_at/backup_at, time_source (HFS+ GMT vs classic-HFS local wall clock), compressed, compression_type and resource_fork_size. |
| `hfs_open(image)` | all | Opens an HFS+ filesystem image and returns a handle. Returns (result, err). |
| `hfs_read_file(handle, path)` | all | Reads a file's bytes from an opened HFS+ image. |
| `mft_parse(path)` | all | Parses an NTFS Master File Table into a per-record timeline. Auto-detects a standalone $MFT file (FILE-signature record stream, e.g. KAPE/FTK/icat) vs a full NTFS volume image. Each entry has $STANDARD_INFORMATION and $FILE_NAME MAC times (unix + iso), reconstructed path, size, sequence, and hard-link count. The record size is read from the first record header rather than assumed, and skipped counts records that would not parse. Returns {source_type, record_size, count, skipped, entries:[{record, parent_record, in_use, is_directory, name, path, size, allocated_size, sequence, hard_links, file_attributes, si_*, fn_*}]}. Returns (result, err). |
| `ntfs_close(handle)` | all | Closes an NTFS handle and releases its file. |
| `ntfs_list_files(handle, dir)` | all | Lists entries under a directory in an opened NTFS image. |
| `ntfs_metadata(handle, path)` | all | Returns metadata for a file/directory in an opened NTFS image, including the $STANDARD_INFORMATION created_at/modified_at/accessed_at/changed_at times and the readability flags (resident, sparse, compressed, encrypted, blocking_error). |
| `ntfs_open(image)` | all | Opens an NTFS filesystem image and returns a handle. Returns (result, err). |
| `ntfs_read_file(handle, path)` | all | Reads a file's bytes from an opened NTFS image. |
| `xfat_close(handle)` | all | Closes an exFAT handle and releases its file. |
| `xfat_list_files(handle, dir)` | all | Lists entries under a directory in an opened exFAT image, with created_at/modified_at/accessed_at, per-timestamp *_utc_offset_valid flags, attributes and valid_data_size. A nameless entry is reported as "(unnamed)". |
| `xfat_metadata(handle, path)` | all | Returns metadata for a path in an opened exFAT image, including created_at/modified_at/accessed_at with *_utc_offset_valid flags, attributes and valid_data_size (the written portion of size; the remainder is slack). |
| `xfat_open(image)` | all | Opens an exFAT filesystem image and returns a handle. Returns (result, err). |
| `xfat_read_file(handle, path)` | all | Reads a file's bytes from an opened exFAT image. Content is staged through a temporary file because libxfat extracts to a path, so reads are capped at 32 MiB. |
| `xfs_close(handle)` | all | Closes an XFS handle and releases its file. |
| `xfs_list_files(handle, dir)` | all | Lists entries under a directory in an opened XFS image, with file_type from the directory record. A damaged inode no longer aborts the listing: that entry is reported with inode_error set and size 0. |
| `xfs_metadata(handle, path)` | all | Returns metadata for a path in an opened XFS image, including created_at/modified_at/accessed_at/changed_at and needs_repair (the filesystem was left inconsistent and its metadata should be treated with suspicion). |
| `xfs_open(image)` | all | Opens an XFS filesystem image and returns a handle. Returns (result, err). |
| `xfs_read_file(handle, path)` | all | Reads a file's bytes from an opened XFS image. |

## Disk Image Forensics (17)

Container and partition-table parsers: raw images, EWF/E01, VHD/VHDX (with differencing chains), and MBR/GPT partition tables.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `ewf_close(handle)` | all | Closes an EWF handle and its segment files. |
| `ewf_metadata(handle)` | all | Returns EWF metadata (version, sectors/chunks, digests, media info, sector_size, compression_method). chunk_tables_invalid counts chunk-table groups that failed both their primary and backup checksum — their data decoded unverified and should be treated as suspect; chunk_tables_recovered, observed_chunk_count and acquisition_error_count report the rest of the integrity picture. |
| `ewf_open(segments)` | all | Opens an EWF/E01 image (a segment path or an array of segment paths). Returns (result, err). |
| `ewf_read_at(handle, offset, length)` | all | Reads length bytes at an offset from an EWF image (length capped at 32 MiB). |
| `raw_close(handle)` | all | Closes a raw image handle. |
| `raw_metadata(handle)` | all | Returns {file_size, assumed_sector_size, sector_size_assumed} (raw images carry no real sector-size metadata). |
| `raw_open(image)` | all | Opens a raw disk image and returns a handle. Returns (result, err). |
| `raw_read_at(handle, offset, length)` | all | Reads length bytes at an offset from a raw image (length capped at 32 MiB). |
| `table_close(handle)` | all | Closes a partition-table handle. |
| `table_list_partitions(handle)` | all | Lists partitions with LBA ranges, absolute start_byte/length_byte, type, name, flags, and hex type_code/attributes. Use start_byte rather than start_lba * block_size, which mislocates every partition on a table parsed at a non-zero offset. |
| `table_open(image)` | all | Opens a disk image and parses its partition table(s) (MBR/GPT). warnings reports suspicious-but-parsable findings (out-of-bounds entries, overlapping extents, hybrid MBR, truncated entry counts); candidates lists every scheme that parsed cleanly, so more than one means the media was ambiguous. Returns (result, err). |
| `table_partition_info(handle, index)` | all | Returns details for a single partition by index, including absolute start_byte/length_byte. |
| `vhdi_close(handle)` | all | Closes a VHD/VHDX handle. |
| `vhdi_map_offset(handle, offset)` | all | Maps a virtual offset to a backing file offset. Returns {virtual_offset, mapped, file_offset}. |
| `vhdi_metadata(handle)` | all | Returns VHD/VHDX metadata (format, disk_type, virtual_size, block/sector size, identifiers), the differencing-chain state (needs_parent, chain_complete, chain_depth, parent_resolve_error) and the VHDX log state (is_dirty, has_log, log_replayed). |
| `vhdi_open(image)` | all | Opens a VHD/VHDX disk image and returns a handle. Returns (result, err). |
| `vhdi_read_at(handle, offset, length)` | all | Reads length bytes at a virtual offset from a VHD/VHDX image (length capped at 32 MiB). |

## Windows Artifacts (4)

Execution and shell-activity artifacts: Prefetch, Windows Event Logs (EVTX), shell links (LNK), and Jump Lists.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `evtx_parse(path)` | all | Parses a Windows Event Log (.evtx). Walks every chunk and decodes each record's BinXML (templates + substitutions) into the fully-expanded event tree, plus summary fields per record. Returns {source, chunk_count, count, records:[{record_id, timestamp, timestamp_iso, event_id, event_record_id, level, channel, computer, provider, event}]}. Returns (result, err). |
| `jumplist_parse(path)` | all | Parses a Windows Jump List (recent/pinned destinations). Auto-detects *.automaticDestinations-ms (OLE compound file: numbered shell-link streams + a DestList MRU/metadata stream) and *.customDestinations-ms (concatenated shell links). Each entry merges DestList metadata (last_access, pinned, hostname) with the embedded shell-link target. Returns {type, format_version, entry_count, pinned_count, entries:[{stream_id, target, arguments, working_dir, name, last_access, last_access_iso, pinned, hostname}]}. Returns (result, err). |
| `lnk_parse(path)` | all | Parses a Windows shell link (.lnk): header (attributes, creation/access/write FILETIME->unix), decoded LinkFlags, LinkInfo local_base_path (target), and StringData (name, relative_path, working_dir, arguments, icon_location). Returns (result, err). |
| `prefetch_parse(path)` | all | Decodes a Windows Prefetch (.pf) file — program execution evidence. Transparently decompresses the Win10/11 MAM (Xpress-Huffman) container and parses the SCCA format for XP (v17), Vista/7 (v23), Win8.1 (v26), and Win10/11 (v30/v31). Returns {version, executable, prefetch_hash, run_count, run_times[], files_loaded[], file_count, volumes:[{device_path, serial, created, created_iso}], compressed}. Returns (result, err). |

## Unix Artifacts (1)

Unix log artifacts: RFC 5424 / RFC 3164 syslog parsing.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `syslog_parse(path)` | all | Parses a Unix syslog file into structured entries, auto-detecting RFC 5424 (IETF, ISO-8601) and RFC 3164 (BSD) per line; unmatched lines are kept as raw messages. RFC 3164 lines omit the year, so the current year is assumed. Each entry has a `ts` unix field for timeline_merge/timeline_sort. Returns {count, entries:[{format, priority, facility, severity, timestamp, ts, host, app_name, pid, msgid, structured_data, message}]}. Returns (result, err). |

## Browser Artifacts (4)

Chromium/Firefox history, cookies, and downloads, plus generic read-only SQLite querying (forensically safe: originals are never modified).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `browser_cookies(path)` | all | Parses a Chromium (Cookies) or Firefox (cookies.sqlite) cookie database. Chromium cookie values are OS-encrypted; such rows are reported with encrypted=true and an empty value (decryption needs OS keys). Returns {browser, count, entries:[{host, name, value, path, expires, expires_iso, secure, http_only, encrypted, browser}]}. Returns (result, err). |
| `browser_downloads(path)` | all | Parses download records from a Chromium (History downloads table) or Firefox (places.sqlite moz_annos) database; Firefox support is best-effort (destination file URI). Returns {browser, count, entries:[{url, target_path, bytes_total, bytes_received, start_time, end_time, state, mime_type, browser}]}. Returns (result, err). |
| `browser_history(path)` | all | Parses a Chromium (History) or Firefox (places.sqlite) history database into normalized visit entries, auto-detecting the schema and converting timestamps to unix. Returns {browser, count, entries:[{url, title, visit_count, last_visit, last_visit_iso, browser}]}. Returns (result, err). |
| `sqlite_query(path, sql, params?)` | all | Runs a read-only SQL query against a SQLite database, pure-Go (no cgo). The database (+ any -wal/-shm sidecars) is copied to a temp file first, so the original is never modified or lock-contended — safe for forensic DBs held open by a running app. Optional params is an ARRAY of bind values for a parameterized query. Returns {columns, row_count, truncated, rows:[{col: value}]}. Returns (result, err). |

## Forensic Timeline (5)

Normalize timestamps across epochs and merge/sort artifact events into a single supertimeline; Sleuth Kit bodyfile/mactime interop.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `bodyfile_parse(path)` | all | Parses a Sleuth Kit bodyfile (MD5\|name\|inode\|mode\|UID\|GID\|size\|atime\|mtime\|ctime\|crtime) into an array of entry hashes. Returns (entries, err). |
| `mactime(entries)` | all | Builds a chronological MAC-time timeline from bodyfile_parse entries: one row per distinct time with a MACB flag string (m/a/c/b, "." where absent), sorted by ts then name (ts field composes with timeline_merge). |
| `timeline_merge(sources, field?)` | all | Flattens an array of event arrays into one supertimeline sorted by a numeric timestamp field (default "ts"). |
| `timeline_sort(events, field?)` | all | Returns events (array of hashes) sorted ascending by a numeric timestamp field (default "ts"); events missing the field sort last. Stable. |
| `timestamp_normalize(value, format?)` | all | Normalizes a timestamp to {unix, unix_ms, iso, format}. Formats: unix (s/ms/us/ns), filetime (Windows), webkit/chrome, dos (packed 32-bit), iso (RFC3339 string). Default "auto" detects unix magnitude or parses an ISO string. Returns (result, err). |

## Email Forensics (5)

Parse raw email into headers/body/attachments/URLs and cryptographically verify DKIM (with SPF/DMARC reporting).

| Builtin | Platforms | Description |
| --- | --- | --- |
| `email_attachments(raw)` | all | Extracts attachment metadata/content details from raw email input. |
| `email_headers(raw)` | all | Parses and returns message headers from raw email input. |
| `email_parse(raw)` | all | Parses a raw email message into headers, body parts, and attachments. |
| `email_spf_dkim(raw)` | all | Cryptographically verifies DKIM signatures (public key via DNS) and reports SPF/DMARC. SPF is reported as recorded by the receiving MTA; DMARC combines the reported result with DKIM alignment. |
| `email_urls(raw)` | all | Extracts and normalizes URLs from email headers and body. |

## Hash-Set Forensics (3)

NSRL-style known-file hash sets for include/exclude filtering.

| Builtin | Platforms | Description |
| --- | --- | --- |
| `hashset_close(handle)` | all | Frees a loaded hash set. Returns (bool, err). |
| `hashset_contains(handle, hash)` | all | Returns whether a hash is in a loaded set (case-insensitive). Returns (bool, err). |
| `hashset_load(path)` | all | Loads a file of hashes (one per line, or CSV/NSRL where the hash is the first field) into an in-memory set. Skips headers/comments/non-hex. Returns {handle, count}. Returns (result, err). |

