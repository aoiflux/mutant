# Secure Networking & Traffic Interception

Mutant ships a networking toolkit in its standard library so that tools such as
TLS clients/servers and mitmproxy-style interception proxies can be written
entirely in Mutant source. See the [Capability Reference](CAPABILITY_REFERENCE.md#network-33)
for the full network builtin table.

The toolkit is split into three layers:

1. **Stream sockets & TLS sessions** — connect, listen, accept, read, write,
   and upgrade connections to TLS (client or server side).
2. **X.509 certificate authority** — generate a CA and mint / sign leaf
   certificates on demand (the core primitive an interception proxy needs).
3. **HTTP message inspection** — parse and rebuild HTTP requests and responses,
   either from a string or directly off a live connection with correct
   framing.

All fallible builtins follow the language convention of returning
`(result, err)`; destructure with `let value, err = ...`.

Two builtins additionally report *recoverable* conditions inside the returned
hash instead of through `err`, so that a polling loop is not forced to abort:

- `net_conn_read` — I/O problems (including read timeouts) land in the result's
  `error` field, with end-of-stream in `eof`. Its `err` return only fires for
  bad arguments or an unknown handle, so always check **both**:
  `if (err) { ... } else if (msg["error"] != "") { ... }`.
- `net_accept` — an expired accept timeout is a successful call returning
  `ok=false, timeout=true` with `err` null. Genuine accept failures set both
  the hash's `error` field and `err`.

Everything else reports failure through `err` alone.

---

## 1. Sockets and TLS sessions

Connections and listeners are referenced by an integer **handle**. Always close
them with `net_conn_close` / `net_listen_close` when done.

| Builtin | Signature | Returns |
| --- | --- | --- |
| `net_connect` | `(address, timeoutMs)` | connection handle |
| `net_tls_connect` | `(address, timeoutMs, options?)` | connection handle |
| `net_conn_write` | `(handle, data, timeout_ms?)` | bytes written (write deadline: default 30s, or `timeout_ms`; `<=0` blocks forever) |
| `net_conn_read` | `(handle, maxBytes, timeoutMs)` | `{data, bytes, eof, error}` (`maxBytes` ≤ 32 MiB) |
| `net_conn_info` | `(handle)` | addresses + negotiated TLS session |
| `net_conn_close` | `(handle)` | bool |
| `net_listen` | `(address)` | listener handle |
| `net_tls_listen` | `(address, certPem, keyPem, options?)` | listener handle |
| `net_accept` | `(listener, timeoutMs)` | `{ok, handle, remote_addr, timeout, error}` |
| `net_listen_close` | `(handle)` | bool |
| `net_tls_upgrade_server` | `(handle, certPem, keyPem, options?)` | handshake info |
| `net_tls_upgrade_client` | `(handle, options?)` | handshake info |

**Client TLS options** (`net_tls_connect`, `net_tls_upgrade_client`):
`server_name`, `insecure` (skip verification), `alpn` (array), `min_version`
(`"1.0"`..`"1.3"`), `ca_cert` (PEM roots to pin), `client_cert` + `client_key`
(PEM, for mutual TLS).

**Server TLS options** (`net_tls_listen`, `net_tls_upgrade_server`):
`alpn`, `min_version`, `client_ca` (PEM; requires and verifies client certs for
mutual TLS).

`handshake_timeout_ms` (default 15000) applies to the two upgrade builtins only,
which drive the handshake themselves. `net_tls_connect` bounds its handshake
with its own `timeoutMs` dial timeout, and `net_tls_listen` handshakes lazily on
first use of the accepted connection.

`net_accept` with `timeoutMs <= 0` blocks; a positive timeout lets a loop poll
without aborting (`ok=false, timeout=true` on expiry).

### Example: verified TLS client

```
let conn, err = net_connect("example.com:443", 5000);
let opts = {"server_name": "example.com", "min_version": "1.2"};
let info, err = net_tls_upgrade_client(conn, opts);
putln("negotiated ", info["tls_version"]);       // e.g. TLS1.3
```

---

## 2. Certificate authority

| Builtin | Signature | Returns |
| --- | --- | --- |
| `tls_generate_ca` | `(options?)` | `{cert_pem, key_pem, serial}` |
| `tls_generate_cert` | `(options?)` | `{cert_pem, key_pem, serial}` (self-signed leaf) |
| `tls_sign_cert` | `(caCertPem, caKeyPem, options?)` | `{cert_pem, key_pem, serial}` (CA-signed leaf) |

Options: `common_name`, `organization`, `dns_names` (array), `ip_addresses`
(array), `days`. Keys are ECDSA P-256; certificates are PEM-encoded.

`tls_sign_cert` is what makes interception possible: mint a leaf certificate for
whatever host the client asked for, signed by a CA the client already trusts.

```
let ca, err = tls_generate_ca({"common_name": "Mutant Dev CA"});
let ca_cert = ca["cert_pem"];
let ca_key = ca["key_pem"];
let leaf_opts = {"common_name": "example.com", "dns_names": ["example.com"]};
let leaf, err = tls_sign_cert(ca_cert, ca_key, leaf_opts);
```

---

## 3. HTTP message inspection

| Builtin | Signature | Returns |
| --- | --- | --- |
| `http_parse_request` | `(raw)` | `{method, url, path, host, proto, query, headers, body}` |
| `http_parse_response` | `(raw, method?)` | `{status, status_text, proto, headers, body}` (pass the method to read a response to `HEAD`) |
| `http_build_request` | `(request)` | raw request string (adds `Content-Length` when a body is present and none was supplied; refuses one that disagrees with the body) |
| `http_build_response` | `(response, method?)` | raw response string (same, and refuses the same disagreement; a 1xx, 204, 304 or a response to `HEAD` is never given a `Content-Length` and is refused if a body comes with it) |
| `http_conn_read_request` | `(handle, timeoutMs)` | parsed request off a live socket |
| `http_conn_read_response` | `(handle, timeoutMs, method?)` | parsed response off a live socket (pass the method to read a response to `HEAD`) |

The `http_conn_read_*` builtins read exactly one message with correct
`Content-Length` / chunked framing. The request line and header block together
are capped at 1 MiB and the body at 32 MiB, and a message past either cap is
refused rather than truncated -- a result is always a whole message. To inspect
one whose body may be larger, take the head with `http_conn_read_request_head`
or `http_conn_read_response_head` and stream the body with `net_conn_read`:
reading only the head leaves the body on the connection and unbounded. A head
carrying more than 100 header fields is refused rather than trimmed, by every
builtin on this page that returns a `headers` hash and by `http_get`,
`http_post` and `http_request`: the cost of a field is not its length, so a
bound counted in bytes does not see a head of a hundred thousand five-byte
fields. Repeats of one field name each count as a field. Byte reads
(`net_conn_read`) and framed reads share the same buffered stream per handle, so
they can be mixed safely on one connection.

**A refusal does not close the connection.** None of these builtins closes a
handle on any error, and that is deliberate: closing a `net/http` body consumes
whatever is left of it, so closing after a refusal would drain the body of the
message just refused -- and against a peer that declares a body and never sends
it, that drain waits for the deadline. The handle stays the script's, so a
script that keeps reading after a refused message must `net_conn_close` it
itself, or it leaks a descriptor per refusal.

The same 32 MiB body cap applies to `http_get`, `http_post` and `http_request`,
whose read was unbounded until it was capped. Those three have no streaming
form, so a larger download is refused outright; the status and headers are still
reported, because they arrived, and the body is dropped rather than returned
cut short. They also report where the answer came from -- `final_url`,
`redirects` and `final_method` -- because they follow redirects, including to
another host, and a redirect that leaves `https` for plain `http` is refused.

**The response to a `HEAD` request needs the method.** A `HEAD` response carries
the `Content-Length` of the representation that was asked about and no body at
all, and nothing in the message itself says which of the two a length is -- only
the request's method does, and the four builtins above take it as an optional
last argument. Without it the read waits for a body that is never sent and fails
(`http_parse_response`) or waits until the deadline (`http_conn_read_response`),
which is why a relay could read the `HEAD` request and not its answer. Pass the
method a relay already read with `http_conn_read_request`; only `HEAD` changes
anything, so it can be passed on every message. It changes three things:
`http_parse_response` and `http_conn_read_response` frame the message with no
body; `http_conn_read_response_head` reports `content_length` 0 and `chunked`
false, because those two fields say what to read off the connection next and the
answer is nothing, while the declared length stays in `headers` where the
evidence belongs; and `http_build_response` keeps that declared length instead
of refusing it for disagreeing with an empty body.

**What `http_request` sends.** Its `headers` are sent as given, with three
exceptions, because `net/http`'s client takes those three off its own request
structure and ignores the header fields: a `Host` is sent as the request's host,
where it used to be dropped in favour of the URL's; a `Content-Length` that
disagrees with the body is refused, naming both numbers, and one that agrees is
dropped, since the body's own length is what gets written; and a
`Transfer-Encoding` is refused, because the body given here is framed for you --
write the request with `net_conn_write` to frame it yourself. Two keys that
differ only in case name one field after `net/http` canonicalises them, so one
value would be sent and the other dropped; that is refused too.

In a `headers` hash, a field that arrived on more than one line is combined into
one comma-separated value, except `Set-Cookie`, which [RFC 9110 section
5.3](https://www.rfc-editor.org/rfc/rfc9110#section-5.3) names as the one field
that may not be folded -- a cookie's `Expires` attribute holds a comma of its
own, so the join could not be undone. It is a list, one element per line and a
list whether one cookie arrived or five, and `http_build_response` writes one
field line per element.

**Field names are canonicalised, and their original spelling is not recoverable.**
A server's `ETag` arrives as `Etag`, and a rebuilt message writes the
canonical spelling. No meaning is lost -- a field name is case-insensitive
([RFC 9110 section 5.1](https://www.rfc-editor.org/rfc/rfc9110#section-5.1)) and
every receiver reads the two the same way -- but the casing a peer chose is a
fingerprinting signal, so a proxy built on these builtins is detectable by the
server it relays to, and a recorded message is not byte-exact in its header
names. Preserving it would mean replacing `net/http`'s parser, which this
project is not going to do. If byte-exact header names are what an examination
needs, read the message with `net_conn_read` and parse the bytes yourself.

---

## 4. WebSocket frames

| Builtin | Signature | Returns |
| --- | --- | --- |
| `ws_accept_key` | `(client_key)` | the `Sec-WebSocket-Accept` value, so a proxy can answer the 101 itself |
| `ws_read_frame` | `(handle, timeoutMs)` | `{fin, rsv1, rsv2, rsv3, opcode, payload, masked, length, is_control}`, unmasked |
| `ws_write_frame` | `(handle, opcode, payload, mask, timeout_ms_or_flags?)` | bytes written |

These sit on the same buffered stream as the `http_conn_*` builtins, so a
connection is read as HTTP up to the `101 Switching Protocols` and as frames
afterwards, on the one handle.

**Relaying a frame means handing the hash back.** The fifth argument of
`ws_write_frame` is either the write deadline, as it has always been, or a hash
carrying the frame's own `fin`, `rsv1`, `rsv2`, `rsv3` and `timeout_ms`. Every
other key is ignored, so the hash `ws_read_frame` returned can be passed whole
and the frame goes back out with the first byte it arrived with. Without that,
the pair could not reproduce what it had just read: `RSV1` is
permessage-deflate, which Chrome and Firefox negotiate by default, so a
compressed frame was relayed with the compression flag cleared and the far side
read the payload as text; and `FIN` was forced on, so the first fragment of a
message was relayed as a whole one and the continuation that followed was a
protocol error. `masked` is deliberately not read from the hash: a client masks
and a server must not ([RFC 6455 section
5.3](https://www.rfc-editor.org/rfc/rfc6455#section-5.3)), so masking belongs to
the direction a frame is being written in and stays the fourth argument.

Two frames the standard does not allow are refused rather than written. An
opcode outside 0 to 15 does not fit the four bits a frame has for it, and used
to be masked into a different kind of frame -- `16` went out as opcode 0, a
continuation. A control frame (opcode 8 and up) carrying more than 125 bytes, or
with `fin` false, is what [RFC 6455 section
5.5](https://www.rfc-editor.org/rfc/rfc6455#section-5.5) requires a peer to fail
the connection over, so a close frame with a 200-byte reason was a dropped
connection and not a close anyone read. A reserved opcode that does fit is still
written: reproducing one is a thing an examiner may need to do.

---

## Putting it together: an interception proxy

The CONNECT interception flow (see `examples/network/mitmproxy.mut`):

```
                    client                     mutant proxy                    upstream
GET/CONNECT  ───────────────────▶  net_accept + http_conn_read_request
                                    │  (CONNECT host:443)
200 Established  ◀──────────────────┤  net_conn_write
                                    │  tls_sign_cert(ca, host)
   TLS handshake  ◀────────────────▶  net_tls_upgrade_server(client, leaf)
real request (encrypted) ─────────▶  http_conn_read_request   ── inspect ──▶
                                    │              net_connect + net_tls_upgrade_client
                                    │              http_build_request ─────────▶  origin
                                    │              http_conn_read_response ◀─────  origin
response  ◀─────────────────────────┤  http_build_response + net_conn_write
```

Run it and point a client's HTTP+HTTPS proxy at `127.0.0.1:8080`, trusting the
CA certificate it prints at startup.

---

## Language gotchas (pre-existing, not specific to these builtins)

Writing multi-step network programs surfaces three parser/VM quirks worth
knowing; the examples are written to avoid them:

1. **No `;` after a `for (...) { }` block.** A trailing semicolon there is
   parsed as an empty statement and fails (`no prefix parse function for ;`).
2. **Don't pass array/hash *literals* as call arguments** alongside other
   arguments — bind the literal to a `let` first. Passing a composite literal
   inline can corrupt an earlier argument. Safe:
   `let opts = {...}; f(a, b, opts);`
3. **Avoid top-level `return`.** Wrap program logic in a function and call it;
   `return` inside a function behaves correctly, but a top-level `return`
   misbehaves.
