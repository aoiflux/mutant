# Binary Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/binary/binary_analysis_example.mut --password <password>
mutant examples/binary/binary_analysis_example.mu --dev --password <password>
```

Scripts:
- binary_analysis_example.mut
- binary_triage_sections_entropy.mut
- ioc_event_triage.mut
- static_bin_analysis.mut

Notes:
- Some scripts use examples/data or root fixtures in examples.
