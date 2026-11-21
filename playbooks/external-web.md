# Playbook — External Web Application

Ordered runbook. Work top to bottom; do not jump to exploitation before mapping.

## Prerequisites

- [ ] `scope.md` signed, in scope list copied into `assets.txt`
- [ ] Engagement dir created: `engagements/<target>-<date>/`
- [ ] `coverage.md` initialized with every in-scope host
- [ ] Proxy configured (Burp/Caido) and browser CA trusted
- [ ] Source IP registered with the client if they allowlist

## Phase 0 — Baseline (30 min)

| Step | Command | Output |
| --- | --- | --- |
| Fingerprint | `httpx -u https://target -td -title -status-code -web-server` | stack |
| WAF | `wafw00f https://target` | vendor |
| Headers | `curl -sI https://target` | security headers, cookies |
| robots/sitemap | `curl -s https://target/robots.txt` | hidden paths |
| TLS | `testssl.sh https://target` | cert SANs, weak ciphers |
| Baseline response | save a normal GET to `poc/baseline.txt` | size, timing |

Decision: if a WAF blocks the first probe, stop fuzzing and switch to low-rate manual testing. Do not burn the engagement on a 403 wall in the first hour.

## Phase 1 — Asset discovery

```bash
../scripts/recon.sh target.com engagements/<target>-<date>/recon
```

- [ ] All subdomains resolved and probed
- [ ] Non-standard ports identified
- [ ] Historical URLs collected (`gau`, `waybackurls`)
- [ ] JS bundles pulled and scanned for endpoints and secrets
- [ ] Cloud storage naming patterns checked
- [ ] `coverage.md` updated with every new host

## Phase 2 — Mapping

- [ ] Crawl authenticated and unauthenticated
- [ ] Enumerate directories per host (`ffuf` raft-large, extensions)
- [ ] Vhost discovery
- [ ] Parameter discovery (`arjun`, `unfurl keys`)
- [ ] API docs, Swagger/OpenAPI, GraphQL introspection
- [ ] Identify roles: anonymous, user, admin, tenant boundaries
- [ ] Note every input: query, body, header, cookie, path segment

Exit: you can draw the app's object model and role matrix.

## Phase 3 — Authentication

- [ ] Registration flow abuse (duplicate email, role in signup body)
- [ ] Login: username enumeration, lockout, default creds
- [ ] Password reset: host header, token predictability, reuse
- [ ] MFA: bypass, code reuse, backup codes, response manipulation
- [ ] Session: fixation, lifetime, logout invalidation, cookie flags
- [ ] JWT: `jwt_tool -M at`, alg confusion, kid/jku injection, weak secret
- [ ] OAuth: redirect_uri, state, PKCE, implicit flow
- [ ] SAML: XSW, comment injection, signature not required

## Phase 4 — Access control (highest hit rate)

- [ ] IDOR on every object id, both directions, both roles
- [ ] BFLA: call admin endpoints with user token
- [ ] Mass assignment: add `role`, `isAdmin`, `tenantId`, `verified`
- [ ] Method swap: GET → PUT/DELETE/PATCH
- [ ] Version downgrade: `/v2/` → `/v1/`
- [ ] Tenant isolation via header/subdomain/claim
- [ ] Forced browsing: `/admin`, `/internal`, `/debug`, `/actuator`

## Phase 5 — Injection

Run in this order, cheapest first:

1. SQLi on every parameter with a database behind it
2. SSTI on any value reflected into a template
3. Command injection on any system-touching input
4. SSRF on any URL/file parameter
5. XXE on any XML body or file upload
6. Deserialization on any opaque blob or cookie
7. LDAP/XPath on directory-backed search

Per finding: reproduce, capture raw request/response, add to `findings.yaml`.

## Phase 6 — Business logic and race

- [ ] Price, quantity, currency, discount tampering
- [ ] Workflow step skipping and replay
- [ ] Coupon/redeem/transfer race (single-packet or parallel)
- [ ] Rate limit gaps on OTP, login, search
- [ ] Refund and balance manipulation

## Phase 7 — Request layer and client-side

- [ ] Host header injection, cache poisoning/deception
- [ ] Request smuggling (CL.TE, TE.CL, H2)
- [ ] CORS misconfiguration
- [ ] CSRF on state-changing endpoints
- [ ] XSS: reflected, stored, DOM — execute, do not assume
- [ ] Prototype pollution, postMessage, DOM clobbering
- [ ] Open redirect and subdomain takeover

## Phase 8 — Consolidation

- [ ] Every finding has a second reproduction
- [ ] Chains documented (`F-01 + F-04 → ATO`)
- [ ] Severity vectors justified in `findings.yaml`
- [ ] `coverage.md` shows no untested in-scope host
- [ ] Cleanup log: test accounts, uploaded files, markers

## Phase 9 — Delivery

```bash
python3 ../scripts/report.py findings.yaml --outdir report/
```

- [ ] `report.md` reviewed for reproducibility
- [ ] Exec summary written by a human, not templated
- [ ] Evidence index matches `poc/`
- [ ] Retest steps included per finding

## Exit criteria

Objective met, or all in-scope surface covered per `coverage.md`, or window closed. Write the handoff.
