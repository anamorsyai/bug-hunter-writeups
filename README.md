# Bug Hunter Daily Writeups

Enhanced, instructor-style rewrites of real HackerOne / Medium / disclosed writeups.
Start here for 2026 > 2025 > 2024, focused on commonly found + high-paid: IDOR, XSS, SSRF, SQLi, Auth/SSO, RCE.

## Index

| Date | Title | Vuln | Bounty | Source |
|------|-------|------|--------|--------|
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
