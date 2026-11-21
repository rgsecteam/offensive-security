# CVSS 3.1 Presets

Starting vectors for common findings. Always adjust `PR`, `UI`, `S`, and the CIA triad to the actual context — a vector copied without justification is a failed report.

## Critical (9.0–10.0)

| Finding | Vector | Score |
| --- | --- | --- |
| Pre-auth RCE | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Pre-auth RCE, scope change | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 |
| Auth RCE (low priv) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 |
| SQLi full read/write | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Auth bypass to admin | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Default admin credentials | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |
| Deserialization RCE | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 |

## High (7.0–8.9)

| Finding | Vector | Score |
| --- | --- | --- |
| SQLi read-only | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| Stored XSS, privileged victim | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | 8.2 |
| IDOR full account takeover | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | 8.1 |
| SSRF to cloud metadata | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` | 7.6 |
| Auth RCE, high complexity | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 |
| Path traversal arbitrary read | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 |
| Local privesc to root/SYSTEM | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 |
| JWT signature bypass | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 → contextualize to 8.x if role-limited |

## Medium (4.0–6.9)

| Finding | Vector | Score |
| --- | --- | --- |
| Reflected XSS | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 |
| Stored XSS, low-value victim | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 |
| IDOR on PII (read) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 |
| CSRF on state change | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | 6.5 |
| SSRF, internal only | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` | 5.4 |
| Open redirect (auth flow) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | 5.4 |
| Information disclosure | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |
| Missing rate limit on OTP | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 |

## Low (0.1–3.9)

| Finding | Vector | Score |
| --- | --- | --- |
| Open redirect | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 |
| Clickjacking | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 |
| Weak TLS config | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` | 3.7 |
| Verbose error messages | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 → downgrade if no sensitive data |
| Cookie without SameSite | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | 4.2 |

## Scoring rules

- **Scope (S)** changes only when the vulnerable component and impacted component differ in security authority (e.g. app → hypervisor).
- **PR:N** only when no authentication is required at all. A self-registered free account is `PR:L`.
- **UI:R** when a victim must perform an action. Stored XSS against an admin who opens a page is still `UI:R`.
- **A:H** requires a genuine availability impact, not just a slow query.
- Never round up to hit a severity band. If the vector says 6.5, it is medium.
