# Playbook: Authorization-Header Presence Bypass — 1 case per test

Target example: API behind HTTP Basic auth where JS builds `Authorization: Basic <b64>`
Full lesson: `2026/2026-06-03-basic-auth-header-presence-bypass.md`
Original: https://medium.com/@0xalr/no-username-no-password-just-a-header-a-3-000-authentication-bypass-9b42432b6c69

Rule: 1 test at a time. Next step only if previous passed. Stop on FAIL.

## 0. Baseline (control, save counts)
- Payload: request WITHOUT any Authorization header.
- PASS if: `401 Unauthorized` (means gate exists). Save the exact 401 body — it is your "patched = safe" reference.
- FAIL: 200 without header = code already broken / no gate → different bug class, stop ladder.

## 1. Credentials parsed?
- Payload: `Authorization: Basic dXNlcjpwYXNz` (b64 `user:pass`, wrong creds).
- PASS if: `401` (value IS being considered; wrong creds rejected).
- FAIL: 200 → server accepts junk base64 → different bug (no cred check at all), stop.

## 2. Empty credentials? ($3,000 case)
- Payload: `Authorization: Basic` (scheme only, nothing after).
- PASS if: `200 OK` → CONFIRMED presence-check bypass.
- FAIL: still 401 → server validates shape/value → try step 3, else stop.

## 3. Degenerate values (cheap variants)
- Payloads one at a time: `Authorization:`, `Authorization: ` (space), `Authorization: Basic `, `Authorization: basic`, `Authorization: Basic =`, `Authorization: Bearer`, `Authorization: Bearer `, `Authorization: nope`.
- PASS if: any returns 200/other non-401 prominence (200, 302, 204, 403 → 403 means gate passed but RBAC blocked → look for anonymous role).
- FAIL: all 401 → try header-name confusion (step 4).

## 4. Header-name confusion
- Payloads: `Proxy-Authorization: Basic`, `X-Authorization: Basic`, `X-API-Key:`, `Authorization: Basic dXNlcjpwYXNz`
  do they change response vs baseline? If a DIFFERENT header produces different code → gate reads that one.
- PASS if: non-401 via alternate header name → proxy/app layer mismatch resolved.
- FAIL: no change → gate is strict on value, stop ladder (this technique set done).

## 5. Breadth (scope = severity)
- Now run the winning header across every endpoint you extracted from JS (or from `/swagger.json`, `/openapi.json`).
- PASS if: >= several endpoints flip 401→200. Record count + the best one (create/modify/delete/admin).
- FAIL: only 1 endpoint → still report, lower impact.

## 6. Impact proof (own account only, never victim)
- With the empty header, hit the most damaging endpoint and capture 1 response: e.g. GET customer list showing own row, or a write you can reverse.

## Notes template
```
Target: <subdomain/API>  auth-builder in JS: y/n (file/line)
0 baseline: 401? ...
1 junk b64: PASS/FAIL
2 empty Basic: PASS/FAIL
3 variants: which switched ...
4 alt header: ...
5 breadth: N/50 endpoints flipped; best = ...
6 proof: endpoint + one field
Severity: critical if CRUD/admin exposed
```