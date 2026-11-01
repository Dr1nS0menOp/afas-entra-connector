# Mutation tests

Tool: `cargo mutants` (v27.1). A mutation test deliberately changes the code
(e.g. `>` to `>=`, `+=` to `*=`, a function that always returns an empty value)
and then runs all tests. If no test fails, the mutant is "missed": a real bug of
that shape would go unnoticed.

## Scope

All modules whose behaviour determines safety or the result:
`plan.rs`, `model.rs`, `afas.rs`, `entra.rs`, `http.rs`, `scim.rs`,
`state.rs`, `sync.rs`.

Not mutated: `config.rs` (configuration validation, with its own rejection
tests), `main.rs` (arguments; covered by the CLI tests) and `error.rs`.

## Result

Every missed mutant was reviewed. Where it was a real gap in the tests, a test
was added and the mutant was run again. Those new tests include: AFAS gives up
after `max_attempts`, token endpoint retries, token refresh within the margin,
a plain 500 versus *bucket full*, not following redirects, timeout on a hanging
server, exact JWT claims, exact limits of all lengths and thresholds, a one-day
employment, the year limits of dates, and unreadable state that must never
count as "first run".

**10 mutants remain. None of them is a behavioural error:**

| Mutant | Why accepted |
| --- | --- |
| `plan.rs:245` `>` → `>=` (pre-hire count) | Equivalent: start = today is always active and falls in the earlier branch |
| `plan.rs:295` `>` → `>=` (`is_new_disable`) | Equivalent: start = today is active; the function already returns at `r.active` |
| `plan.rs:328` `prev_n > 0` → `>= 0` | Equivalent: with 0 previous records `now < prev` can never be true |
| `plan.rs:329` `<` → `<=` | Equivalent: equal counts give a drop of 0, never above the threshold |
| `plan.rs:344` `considered > 0` → `>= 0` | Equivalent: with 0 records there are 0 errors, never above the threshold |
| `entra.rs:166` `<` → `<=` (token margin) | Equivalent: a difference of one nanosecond |
| `entra.rs:305` `!=` → `==` | Only a log line for a 2xx response that is not 202 |
| `afas.rs:103` (2×) | Safety net of 1,000,000 rows; testing it needs a million rows |
| `http.rs:12` `delete !` (proxy flag) | Proxy behaviour comes from reqwest/the OS and cannot be tested locally; in production the system proxy is on |

The exact limits of all thresholds (`min_records`, `max_drop_percent`,
`max_invalid_percent`, `max_disables_per_run`, `max_calls_per_run`) and of
all field lengths are pinned down by separate tests.

Line numbers refer to the code at the time of the mutation run (0.1.0).
