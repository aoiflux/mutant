# Macro Examples

These examples demonstrate Mutant macro syntax and macro-expansion patterns.

Run from repository root, for example:

```bash
mutant gen --src examples/macros/macro_quote_unquote_basics.mut --password test123
mutant examples/macros/macro_quote_unquote_basics.mu --dev --password test123
```

Macros are expanded during compilation, so these examples go through the normal
compile-then-run path with no extra flags.
