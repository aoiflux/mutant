# Security Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/security/security_diagnostics_example.mut --dev
mutant examples/security/security_diagnostics_example.mu --dev
```

Scripts:
- command_sandbox.mut — gate command execution behind a policy, then run what the policy allowed
- security_diagnostics_example.mut
- security_environment_report.mut
- security_quickcheck.mut
- system_forensics_example.mut
