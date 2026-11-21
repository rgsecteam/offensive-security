# Social Engineering (Red Team, In Scope Only)

Only run against people when the RoE explicitly authorizes it, names the target population, and provides a deconfliction contact. Employees are not the enemy; the report is about process failure, not individual failure.

## 1. Pretext design

- **Authority:** IT, HR, legal, auditor
- **Urgency:** password expiry, invoice overdue, MFA re-enrollment
- **Familiarity:** internal tooling, shared drive, known project name
- **Curiosity:** shared document, salary sheet, meeting notes

Keep the pretext consistent across email, landing page, and phone. A single inconsistency kills the campaign.

## 2. Infrastructure

```bash
# Phishing platform
gophish                    # campaign management, templates, tracking

# Reverse proxy phishing (captures session, bypasses MFA)
evilginx2 / evilginx3
modlishka
# Requires: domain, VPS, valid TLS cert, phishlet for the target IdP
```

Domain strategy:

- Lookalike (homoglyph, typosquat, hyphenation)
- Expired domain with historical reputation
- Subdomain of a lookalike (`login.target-sso.com`)
- Aged domain preferred over new registration

Email authentication:

- SPF, DKIM, DMARC aligned to the sending domain
- Warm the domain for 2–3 weeks if the target filters aggressively
- Avoid link shorteners; host the landing page on the phishing domain

## 3. Payload delivery

| Format | Notes |
| --- | --- |
| ISO / IMG | Mounts natively, bypasses MOTW in some configs |
| LNK | Shortcut with embedded command |
| HTA | `mshta` execution |
| OneNote `.one` | Embedded object execution |
| Password-protected ZIP | Bypasses some AV scanning; password in the email body |
| SVG | Script execution in some renderers |
| HTML smuggling | JS builds the payload client-side |

Always test against the client's actual mail gateway first, with approval.

## 4. OAuth consent phishing

1. Register an app in the target tenant (or a multi-tenant app).
2. Request scopes like `Mail.Read`, `Files.Read.All`, `offline_access`.
3. Send a consent link; the user grants access without a password.
4. Use the refresh token to read mail/files.

Detection: app consent policy, admin consent workflow, unusual app registrations.

## 5. Vishing and helpdesk

- Helpdesk MFA reset is the highest-value pretext: call as an employee, claim a lost phone, request MFA re-enrollment.
- Verify what the helpdesk asks for — employee ID, manager name, callback number.
- Record the call only with written approval and legal review.
- Document the exact questions that failed to stop the attack.

## 6. Physical (if in scope)

- Tailgating, badge cloning (`proxmark3`), door bypass
- Reception pretext, vendor/contractor cover
- Document the control that failed, not the person who held the door

## 7. Metrics

| Metric | Meaning |
| --- | --- |
| Delivery rate | Reached inbox |
| Open rate | Opened |
| Click rate | Clicked link |
| Credential submission | Entered credentials |
| MFA bypass | Session captured |
| Report rate | Users who reported it |
| Time to first report | Detection speed |

Report rate is often the most useful number for the client.

## 8. Ethics and deconfliction

- No real credentials stored; hash and discard immediately.
- No lateral movement from a phished account unless explicitly authorized.
- Stop the campaign the moment the client's SOC detects it, if the RoE requires that test.
- Debrief the affected users privately; never name individuals in the report.
- Delete captured data at engagement close, with a signed deletion record.

## 9. Checklist

- [ ] RoE explicitly authorizes social engineering and names the population
- [ ] Deconfliction contact and stop channel confirmed
- [ ] Domain and TLS ready, SPF/DKIM/DMARC aligned
- [ ] Landing page mirrors the real login closely
- [ ] Mail gateway tested with approval
- [ ] Credential handling and deletion process defined
- [ ] Metrics captured
- [ ] Debrief and deletion record delivered
