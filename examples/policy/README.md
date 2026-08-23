# Policy Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/policy/policy_engine_example.mut --password <password>
mutant examples/policy/policy_engine_example.mu --dev --password <password>
```

Scripts:
- policy_engine_example.mut
- policy_inline_allow_deny.mut
