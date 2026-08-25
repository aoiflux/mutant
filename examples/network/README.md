# Network Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/network/cloud_metadata_checker.mut --password <password>
mutant examples/network/cloud_metadata_checker.mu --dev --password <password>
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

Secure networking / interception (see `docs/SECURE_NETWORKING.md`):

- secure_client.mut — open a verified TLS connection and speak HTTP over it
- secure_echo_server.mut — a TLS-terminating echo server with a generated cert
- mitmproxy.mut — an HTTP/HTTPS intercepting proxy with an on-the-fly CA
