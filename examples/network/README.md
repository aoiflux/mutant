# Network Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/network/cloud_metadata_checker.mut --dev
mutant examples/network/cloud_metadata_checker.mu --dev
```

Scripts:

- cloud_metadata_checker.mut
- http_example.mut
- http_recon_fetcher.mut
- http_status_monitor.mut
- ioc_fetcher.mut
- net_example.mut
- network_forensics_example.mut
- network_service_recon_graph.mut
- network_triage_dns_tls.mut
- pcap_offline_analysis.mut
- service_recon.mut — resolve a host, connect-scan a port range, and grab a banner

Secure networking / interception (see `docs/SECURE_NETWORKING.md`):

- secure_client.mut — open a verified TLS connection and speak HTTP over it
- secure_echo_server.mut — a TLS-terminating echo server with a generated cert
- mitmproxy.mut — an HTTP/HTTPS intercepting proxy with an on-the-fly CA

Servers built on `net_serve`, which dispatches each connection to a handler
written in its own file. Run the server; the handler beside it is what it calls:

- concurrent_server.mut / concurrent_server_handler.mut — a concurrent HTTP server
- ws_echo_server.mut / ws_echo_handler.mut — a concurrent WebSocket echo server, RFC 6455 frames over `ws_*`
