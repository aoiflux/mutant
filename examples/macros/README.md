# Macro Examples

These examples demonstrate Mutant macro syntax and macro-expansion patterns.

Run from repository root, for example:

```bash
mutant gen --src examples/macros/macro_quote_unquote_basics.mut --dev
mutant examples/macros/macro_quote_unquote_basics.mu --dev
```

Macros are expanded during compilation, so these examples go through the normal
compile-then-run path with no extra flags.

Scripts:
- macro_quote_unquote_basics.mut — what `quote` and `unquote` each do, one at a time
- macro_rewrite_unless.mut — build a control-flow form the language does not have (`unless`) out of one it does
- macro_mini_dsl_rules.mut — a mini rule DSL: a macro that turns a name and a condition into a match result
