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

Skill `bug-hunter-writeups` auto-triggers, fetches live, enhances, saves here, and git pushes if `origin` exists.

To enable push:
```bash
cd /workspace
git init 2>/dev/null; git remote add origin <your-github-url> 2>/dev/null || true
git add writeups/ && git commit -m "add writeups" && git push -u origin main
```
