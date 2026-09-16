# Lua Examples

Run from repository root (compile, then run the bytecode it writes
beside the source):

```bash
mutant gen --src examples/lua/lua_run_file_example.mut --dev
mutant examples/lua/lua_run_file_example.mu --dev
```

Scripts:
- lua_run_file_example.mut
- lua_run_http_example.mut
- lua_run_string_example.mut
- lua_scoring_engine.mut — embed a Lua scoring rule in the sandbox, so the scoring logic ships separately from the tool
