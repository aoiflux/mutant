# Secure Networking & Traffic Interception (dev-sec)

This branch adds a networking toolkit to the Mutant standard library so that
tools such as TLS clients/servers and mitmproxy-style interception proxies can
be written entirely in Mutant source.

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

---

## 1. Sockets and TLS sessions

Connections and listeners are referenced by an integer **handle**. Always close
them with `net_conn_close` / `net_listen_close` when done.

| Builtin | Signature | Returns |
| --- | --- | --- |
| `net_connect` | `(address, timeoutMs)` | connection handle |
| `net_tls_connect` | `(address, timeoutMs, options?)` | connection handle |
| `net_conn_write` | `(handle, data)` | bytes written |
| `net_conn_read` | `(handle, maxBytes, timeoutMs)` | `{data, bytes, eof, error}` |
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
(PEM, for mutual TLS), `handshake_timeout_ms`.

**Server TLS options** (`net_tls_listen`, `net_tls_upgrade_server`):
`alpn`, `min_version`, `client_ca` (PEM; requires and verifies client certs for
mutual TLS), `handshake_timeout_ms`.

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
| `http_parse_response` | `(raw)` | `{status, status_text, proto, headers, body}` |
| `http_build_request` | `(request)` | raw request string |
| `http_build_response` | `(response)` | raw response string |
| `http_conn_read_request` | `(handle, timeoutMs)` | parsed request off a live socket |
| `http_conn_read_response` | `(handle, timeoutMs)` | parsed response off a live socket |

The `http_conn_read_*` builtins read exactly one message with correct
`Content-Length` / chunked framing (bodies are capped at 32 MiB). Byte reads
(`net_conn_read`) and framed reads share the same buffered stream per handle, so
they can be mixed safely on one connection.

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

Writing multi-step network programs surfaced three parser/VM quirks worth
knowing. All predate this branch; the examples are written to avoid them:

1. **No `;` after a `for (...) { }` block.** A trailing semicolon there is
   parsed as an empty statement and fails (`no prefix parse function for ;`).
2. **Don't pass array/hash *literals* as call arguments** alongside other
   arguments — bind the literal to a `let` first. Passing a composite literal
   inline can corrupt an earlier argument. Safe:
   `let opts = {...}; f(a, b, opts);`
3. **Avoid top-level `return`.** Wrap program logic in a function and call it;
   `return` inside a function behaves correctly, but a top-level `return`
   misbehaves.
