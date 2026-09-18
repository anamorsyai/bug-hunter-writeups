# Bug Hunter Daily Writeups

Enhanced, instructor-style rewrites of real HackerOne / Medium / disclosed writeups.
Start here for 2026 > 2025 > 2024, focused on commonly found + high-paid: IDOR, XSS, SSRF, SQLi, Auth/SSO, RCE.

## Index

| Date | Title | Vuln | Bounty | Source |
|------|-------|------|--------|--------|
| 2026-03-17 | [NASA XXE Regex Bypass to SSRF](2026/2026-03-17-nasa-cmr-xxe-regex-bypass.md) | XXE/SSRF | P1 9.1 | [Bugcrowd NASA](https://bugcrowd.com/disclosures/9d2c7b28-7ff7-439c-9149-f74a883815e3/xml-external-entity-xxe-injection-via-regex-bypass-in-cmr-aql-parsing-enables-ssrf-service-enumeration-and-blind-file-reads) |
| 2026-07-21 | [Essity WP Batch Blind SQLi](2026/2026-07-21-essity-wp-batch-sqli.md) | SQLi Blind | Critical 9.3 | [H1 #3873072](https://hackerone.com/reports/3873072) |
| 2026-06-20 | [Khan Academy Regex Redirect 1-Click ATO](2026/2026-06-20-khan-academy-regex-redirect-ato.md) | Open Redirect / ATO | Critical 9.6 | [H1 #3723458](https://hackerone.com/reports/3723458) |
| 2026-08-05 | [Mozilla Taskcluster GraphQL sift RCE](2026/2026-08-05-mozilla-taskcluster-graphql-rce.md) | RCE / Code Injection | $12,000 | [H1 #3782701](https://hackerone.com/reports/3782701) |
| 2025-02-26 | [GitLab Password Reset Type-Confusion to 0-Click ATO](2025/2025-02-26-gitlab-password-reset-ato.md) | Auth Takeover / CWE-843 | $35,000 | [H1 #2293343](https://hackerone.com/reports/2293343) |

## Structure
- `2026/` - this year disclosures
- `2025/` - last year top paid
- `2024/` - fundamentals still paying
- `TEMPLATE.md` - instructor format

## How to get today's lesson
Ask in chat:
- `give me today's writeup`
- `give me XSS writeup 2025`
- `fetch hackerone IDOR high bounty`

Skill `bug-hunter-writeups` auto-triggers, fetches live, enhances, saves here, and auto-pushes to `main`.

Repo: https://github.com/anamorsyai/bug-hunter-writeups (this folder is the repo root).
```bash
git -C /workspace/writeups add . && git -C /workspace/writeups commit -m "add writeup: <slug>" && git -C /workspace/writeups push origin main
```
