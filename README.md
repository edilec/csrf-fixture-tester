# CSRF Fixture Tester

Offline, read-only comparison of abstract CSRF request fixtures against recorded local middleware decisions. It consumes **no live target URL**, executes no middleware, creates no exploit page, and sends no request. The caller's unit harness records `observedDecision`; this checker tests whether those recorded decisions match a declared origin/token policy. Node.js 22+, zero dependencies. `src/index.mjs` exports `evaluateCsrfFixtures(fixtures, policy, {now, deadline})` and `TOOL_ID`.

```sh
node bin/csrf-fixture-tester.mjs --root examples --policy policy.json --fixtures passing-fixtures.json
node bin/csrf-fixture-tester.mjs --root examples --policy policy.json --fixtures failing-fixtures.json
```

The synthetic examples exit 0 and 1. `--help` prints usage to stderr; normal runs print a bounded human summary to stderr. Stdout contains only the v1 JSON report.

Policy is `{"schemaVersion":"1","expectedOrigin":"https://app.example.invalid","protectedMethods":["POST","PUT","PATCH","DELETE"],"requireOrigin":true,"requireToken":true}`. `expectedOrigin` is an HTTP(S) origin, compared after URL origin canonicalization (so a default port and host case do not create false mismatches). Protected methods are a subset of POST/PUT/PATCH/DELETE and must include POST. Both origin and token requirements must be true. Fixture suite is `{"schemaVersion":"1","complete":true,"cases":[{"id":"valid","request":{"method":"POST","origin":"https://app.example.invalid","tokenState":"valid"},"observedDecision":"allow"}]}`. `origin:null` represents missing origin; `tokenState` is an abstract result `valid`, `missing`, or `invalid`—never a raw token. Every complete passing suite must cover a protected same-origin valid-token allow, same-origin missing-token reject, and mismatched-origin valid-token reject. A recorded decision may be `allow` or `reject`; missing/unsupported decisions are incomplete. This policy intentionally does not infer actual token cryptography or network behavior.

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| policy-invalid | warning | invalid policy (CLI rejects configuration) |
| fixtures-invalid | warning | unsupported or malformed fixture/case |
| fixtures-incomplete | warning | suite declares partial coverage |
| coverage-gap | warning | one required scenario absent |
| decision-missing | warning | no supported recorded decision |
| limit-exceeded | warning | byte, count, depth, or time bound exceeded |
| input-unreadable | warning | fixture unreadable, undecodable, or unparseable |
| unsafe-allowed | error | middleware allowed a request policy rejects |
| safe-rejected | error | middleware rejected a request policy allows |

Reports use code-unit-sorted findings. `@policy` and `@fixtures` are fixed logical roles, not host paths; JSON pointers identify zero-based case ordinals in the invoked file. No case IDs, origins, paths, or token material are echoed. Exit 0 pass, 1 completed policy failure, 2 incomplete or invalid configuration. Invalid usage, root, path, or policy leaves stdout empty; unreadable or ambiguous fixture input emits an incomplete JSON report. Input files must be relative and realpath-confined beneath a declared directory root.

Limits: policy ≤64 KiB, fixture suite ≤1 MiB, ≤1000 cases, JSON depth ≤16, injected deadline 5 seconds. UTF-8 decoding is strict and duplicate JSON object keys, including escaped aliases, are rejected. A bound breach is incomplete. The checker does not prove route coverage, actual middleware execution, browser cookie behavior, or token verification; those remain the caller's responsibility. Run `npm run check` for syntax and tests.
