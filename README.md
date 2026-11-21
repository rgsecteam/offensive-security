# Offensive Security — Agent Skill

A full-lifecycle offensive security skill for AI coding agents. It turns an agent from "knows about pentesting" into an operator that runs the engagement: scope gate, reconnaissance, enumeration, exploitation, privilege escalation, lateral movement, and a report that survives review.

Built for [OpenCode](https://opencode.ai) and Claude Code, with progressive disclosure so the model loads only the reference it needs for the current target.

```
recon → enumerate → exploit → escalate → pivot → report
```

## What's inside

| Path | Contents |
| --- | --- |
| `SKILL.md` | Entry point: operating contract, lifecycle, routing table, checklists, one-liners |
| `references/` | 14 domain deep-dives, loaded on demand |
| `playbooks/` | 4 ordered runbooks for a whole engagement |
| `assets/` | Scope, finding, and report templates; CVSS presets; findings schema |
| `scripts/` | `recon.sh`, `triage.py`, `report.py` |
| `agents/` | 5 subagent definitions, including an independent QA gate |

### References

| File | Covers |
| --- | --- |
| `recon.md` | OSINT, subdomains, DNS, ports, service enumeration, port-wise table |
| `web.md` | Web, API, auth, access control, injection, request layer, client-side |
| `ad.md` | Kerberos, ADCS ESC1–15, ACL abuse, delegation, relay, coercion |
| `linux-privesc.md` | sudo, SUID, cron, capabilities, kernel CVEs, containers, NFS |
| `windows-privesc.md` | Token privileges, service ACLs, UAC, DPAPI, AV/AppLocker |
| `cloud-container.md` | AWS/Azure/GCP privesc, Kubernetes escape, Docker, CI/CD |
| `payloads-c2-pivot.md` | Shells, msfvenom, C2 frameworks, evasion, pivoting, exfil |
| `ctf.md` | CTF categories and shortcuts |
| `reporting.md` | Finding template, CVSS, attack narrative, retest |
| `setup.md` | Kali build-out in 30 minutes, tmux layout, logging wrapper |
| `mobile.md` | Android/iOS, Frida, objection, pinning bypass, exported components |
| `network-infra.md` | Citrix, Fortinet, Ivanti, F5, Pulse, MOVEit, SNMP, IPv6 |
| `ai-llm-security.md` | Prompt injection, tool abuse, RAG poisoning, MCP |
| `social-engineering.md` | Pretexting, GoPhish, Evilginx, OAuth consent, vishing |

## Install

### OpenCode (V2)

```bash
git clone https://github.com/rgsecteam/offensive-security.git ~/tools/offensive-security

# Skill
mkdir -p ~/.config/opencode/skills
ln -sfn ~/tools/offensive-security ~/.config/opencode/skills/offensive-security

# Subagents
mkdir -p ~/.config/opencode/agents
for f in ~/tools/offensive-security/agents/*.md; do
  ln -sfn "$f" ~/.config/opencode/agents/$(basename "$f")
done
```

Symlinks mean `git pull` updates everything in place. Use `cp -r` instead if you prefer a frozen copy.

Project-scoped install (checked into the repo you're testing):

```bash
mkdir -p .opencode/skills .opencode/agents
ln -sfn ~/tools/offensive-security .opencode/skills/offensive-security
for f in ~/tools/offensive-security/agents/*.md; do
  ln -sfn "$f" .opencode/agents/$(basename "$f")
done
```

### Claude Code

```bash
git clone https://github.com/rgsecteam/offensive-security.git ~/tools/offensive-security
mkdir -p ~/.claude/skills
ln -sfn ~/tools/offensive-security ~/.claude/skills/offensive-security
```

The `SKILL.md` format is compatible. The files in `agents/` use OpenCode V2 frontmatter (`mode`, `permissions`) — on Claude Code, use the skill directly or convert the frontmatter to that client's agent format.

### Verify

```bash
ls ~/.config/opencode/skills/offensive-security/SKILL.md
ls ~/.config/opencode/agents/
```

Start a new session and ask for something in scope — the skill is selected by its description, not by a command.

## Usage

```
Use the offensive-security skill to assess app.example.com. Scope is in ~/engagements/example/scope.md
```

```
Use the offsec-operator subagent on this engagement and hand back a report.
```

```
Use the recon-operator subagent to map example.com and rank the surface.
```

```
Review my findings with the finding-reviewer subagent before I send the report.
```

Without a subagent, the main agent reads `SKILL.md`, routes to the matching reference, and works from there.

## Scripts

```bash
# External asset discovery: subdomains → live hosts → ports → tech → screenshots
./scripts/recon.sh example.com ./recon-example

# nmap XML → open-port table (markdown, --csv, -o file)
python3 scripts/triage.py scan.xml

# findings.yaml → report.md + findings.csv + report.sarif
python3 scripts/report.py engagements/example/findings.yaml --outdir report/
```

`recon.sh` skips missing tools instead of failing, so it runs on a partially built box. `report.py` requires PyYAML and nothing else.

## Subagents

| Agent | Role | Boundary |
| --- | --- | --- |
| `offsec-operator` | Lead: state, coverage, scope gate, final report | Delegates, never delegates the scope gate |
| `recon-operator` | Surface mapping and ranking | No exploitation, no brute force |
| `web-operator` | Web/API/client-side exploitation | Two reproductions before a finding |
| `ad-operator` | Kerberos, ADCS, ACL, relay, lateral | Lockout policy read before any spray |
| `finding-reviewer` | Independent reproduction and severity audit | Cannot edit `findings.yaml` |

The reviewer's restriction is enforced by its permission block, not by instruction:

```yaml
permissions:
  - { action: edit, resource: "*", effect: allow }
  - { action: edit, resource: "*/findings.yaml", effect: deny }
```

A FAIL has to be fixed in the finding itself.

## Design decisions

**Progressive disclosure.** `SKILL.md` is the only file read up front. Everything else loads on demand, which keeps the context window free for actual tool output.

**One scope gate, then closed.** Authorization is established once — contract, bounty program scope page, or owned asset. After that the agent does not re-litigate permission on in-scope work, and does not soften findings because they turned out to be serious.

**Coverage ledger.** Every asset × technique pair gets a row. It prevents re-testing and it is the only thing that makes "this target is clean" a defensible statement.

**Verification gate.** Nothing enters `findings.yaml` without a second independent reproduction and a raw evidence file. A version banner is not a vulnerability. A 500 is not RCE.

**Live-target discipline.** Fingerprint with one request before fuzzing, under 10 req/s for discovery, one request at a time for exploitation, read-only proofs (`id`, `whoami`, `SELECT @@version`, `sleep(3)`), and stop conditions on 5xx rate or latency.

**Report from one source.** Findings live in YAML. Markdown, CSV, and SARIF are rendered, never hand-edited.

## Authorization

This repository contains offensive security methodology and tooling. It is dual-use and aimed at no one in particular.

Use it only against systems you own or have explicit written permission to test — a signed contract, a bug bounty program's published scope, a CTF you are enrolled in, or your own lab. Unauthorized access to computer systems is a criminal offence in most jurisdictions, including under the CFAA (US), the Computer Misuse Act (UK), and equivalent legislation elsewhere.

The authors accept no liability for misuse or for damage arising from use of this material. You are responsible for staying inside your scope, your rules of engagement, and the law.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. Useful contributions:

- A reference file for a domain that is missing
- A playbook for an engagement type not covered
- A correction to a command that no longer works against current tooling
- A bug in `scripts/`

Keep the style: command-level, no filler, no moralizing inside the technical content, and every claim reproducible.
