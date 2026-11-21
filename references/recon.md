# Reconnaissance & Enumeration

## 1. Passive

```bash
# Ownership, ASN, netblocks
whois target.com
amass intel -org "Target Inc" -asn
curl -s "https://bgp.he.net/search?search%5Bsearch%5D=target" 

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Subdomains
subfinder -d target.com -all -recursive -silent -o subs.txt
amass enum -passive -d target.com -o amass.txt
assetfinder --subs-only target.com

# Resolve + probe
cat subs.txt | dnsx -silent -a -resp -o resolved.txt
httpx -l resolved.txt -silent -status-code -title -tech-detect -web-server -o live.txt

# Historical URLs
gau --subs target.com | tee gau.txt
waybackurls target.com | tee wb.txt
cat gau.txt wb.txt | uro | sort -u > urls.txt

# Crawl current site
katana -list live.txt -jc -kf all -d 3 -o crawl.txt
```

Search-engine dorks worth automating: `site:target.com -www`, `site:*.target.com`, `inurl:api`, `ext:env|sql|bak|old|log|json`, `"target.com" password`, `site:github.com "target.com"`.

GitHub/GitLab: `org:target`, `"target.com" filename:.env`, `AKIA`, `BEGIN RSA PRIVATE KEY`, `filename:Jenkinsfile`, `filename:.npmrc`.

Shodan: `org:"Target"`, `ssl:"target.com"`, `http.favicon.hash:<mmh3>`, `http.html_hash`, `product:Jenkins`. Censys and FOFA mirror most of these.

Cloud storage: try `target-{dev,prod,backup,assets,media,static,logs}` on S3/GCS/Azure blob. Check `s3.amazonaws.com` DNS for dangling references.

## 2. Active — network

```bash
# Discovery
nmap -sn 10.10.10.0/24
arp-scan -l                              # local segment, fast and accurate

# Full TCP, fast
nmap -p- --min-rate 5000 -Pn -oG allports.txt 10.10.10.10
masscan -p0-65535 --rate 5000 10.10.10.0/24 -oL masscan.txt
naabu -host 10.10.10.10 -p - -rate 2000

# Service/version + default scripts
nmap -sCV -Pn -p 22,80,445,3389 10.10.10.10
nmap -sV -sC -Pn --script vuln -p- 10.10.10.10

# UDP (slow — top 100 first)
nmap -sU --top-ports 100 -Pn 10.10.10.10
nmap -sU -p 53,67,69,111,123,137,138,161,162,500,514,623,1900 10.10.10.10

# Firewall evasion (only with RoE approval)
nmap -f --data-length 200 --source-port 53 -T2 10.10.10.10
```

## 3. Service enumeration

| Port | Service | Commands |
| --- | --- | --- |
| 21 | FTP | `ftp -p host`; anonymous login; `nmap --script ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor` |
| 22 | SSH | banner + version; `ssh-audit host`; weak keys via `nmap --script ssh-hostkey` |
| 25/465/587 | SMTP | `nmap --script smtp-commands,smtp-enum-users,smtp-open-relay`; `smtp-user-enum -M VRFY -U users -t host` |
| 53 | DNS | zone transfer `dig axfr @host target.com`; `dnsrecon -d target.com -t axfr`; `dnsenum` |
| 88 | Kerberos | `nmap -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=DOMAIN,userdb=users` |
| 111 | rpcbind | `rpcinfo -p host`; `showmount -e host` |
| 135 | MSRPC | `impacket-rpcdump @host` |
| 139/445 | SMB | `nxc smb host -u '' -p ''`; `enum4linux-ng -A host`; `smbclient -L //host -N`; `smbmap -H host` |
| 161 | SNMP | `onesixtyone -c community.txt host`; `snmpwalk -v2c -c public host`; `snmp-check host` |
| 389/636 | LDAP | `ldapsearch -x -H ldap://host -s base namingcontexts`; `ldapdomaindump` |
| 512-514 | r-services | `rlogin`, `rsh`, `rexec` — try trusted host files |
| 873 | rsync | `rsync rsync://host/`; `rsync -av host::module ./loot` |
| 1433 | MSSQL | `nxc mssql host -u sa -p ''`; `impacket-mssqlclient`; `nmap --script ms-sql-info,ms-sql-empty-password` |
| 1521 | Oracle | `odat all -s host`; default `scott/tiger`, `system/manager` |
| 2049 | NFS | `showmount -e host`; mount and check `no_root_squash` |
| 2375/2376 | Docker | `curl http://host:2375/version`; `docker -H tcp://host:2375 ps` |
| 3306 | MySQL | `mysql -h host -u root`; `nmap --script mysql-empty-password,mysql-enum` |
| 3389 | RDP | `nmap --script rdp-enum-encryption`; `xfreerdp`; BlueKeep check `rdp-vuln-ms12-020` |
| 5432 | PostgreSQL | `psql -h host -U postgres`; trust auth check |
| 5900 | VNC | `vncviewer`; `nmap --script vnc-info,vnc-brute` |
| 5985/5986 | WinRM | `nxc winrm host -u user -p pass`; `evil-winrm -i host -u user -p pass` |
| 6379 | Redis | `redis-cli -h host`; `INFO`, `CONFIG GET dir`; unauth RCE via cron/SSH keys/module |
| 8080+ | HTTP alt | always probe with httpx; Tomcat/Jenkins/Spring/actuator |
| 9200 | Elasticsearch | `curl host:9200/_cat/indices?v`; `_search?size=100` |
| 11211 | Memcached | `memcstat --servers=host`; `nc host 11211` then `stats items` |
| 27017 | MongoDB | `mongosh --host host`; unauth `show dbs` |
| 6443 | Kubernetes | `curl -k https://host:6443/version`; anon auth check |

## 4. SMB deep dive

```bash
nxc smb 10.10.10.0/24                      # signing, SMBv1, OS, hostname
nxc smb host -u '' -p '' --shares --users --groups --pass-pol
nxc smb host -u user -p pass --shares -M spider_plus
nxc smb host -u user -p pass --lsa --sam --ntds   # needs admin/DA

smbclient -L //host -N
smbclient //host/share -N
smbmap -H host -u user -p pass -R

# Signing disabled -> relay candidate
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt
```

Check for: null sessions, guest access, writable shares, SYSVOL scripts, GPP `cpassword`, backup files, `web.config`, `.kdbx`, SSH keys.

## 5. LDAP without credentials

```bash
ldapsearch -x -H ldap://dc -s base namingcontexts
ldapsearch -x -H ldap://dc -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://dc -b "DC=corp,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  # no preauth
```

## 6. Web surface discovery

```bash
httpx -l ips.txt -ports 80,443,8080,8443,8000,8888 -silent -title -tech-detect -status-code
whatweb -a 3 https://target.com
wafw00f https://target.com
nuclei -u https://target.com -tags tech,exposure,config -severity info,low,medium
nuclei -l live.txt -t ~/nuclei-templates/http/cves/ -severity critical,high
```

## 7. Version → CVE

```bash
searchsploit apache 2.4.49
nuclei -u https://target.com -tags apache
# vendor advisory + changelog diffing is usually faster than exploit DBs
```

## 8. Notes

- Rate limit: `-rl` on nuclei, `--min-rate` on nmap, `-rate` on naabu. Production targets get gentle scans.
- Save raw output; re-parsing beats re-scanning.
- Prefer a single well-targeted scan over a noisy full sweep that trips IDS on the first packet.
