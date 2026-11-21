# CTF Playbook

## 1. First five minutes

```bash
# Always
file *; exiftool *; strings -n 8 * | head -100
binwalk -eM *; foremost -i * -o out
7z l *; unzip -l *; tar tvf *
checksec --file=*
```

Read the challenge description for hints: category, points, author, provided files, connection info.

## 2. Web

- Source: comments, `robots.txt`, `sitemap.xml`, `.git/`, `.env`, `backup.zip`, `www.zip`.
- Cookies/JWT decode, `admin` path brute, param fuzzing.
- LFI: `php://filter`, `/proc/self/environ`, log poisoning.
- SSTI: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` → engine-specific RCE.
- SQLi: `' OR 1=1-- -`, union column count, `sqlmap` as fallback.
- Command injection with filter bypass: `$IFS`, `${IFS}`, `%09`, base64, wildcards.
- PHP tricks: `preg_replace /e`, `assert`, `create_function`, type juggling (`0e`, `==` vs `===`), `extract`, variable variables, `__wakeup`/`__destruct` POP chains.
- SSRF to internal service, gopher for Redis/MySQL.
- Node: prototype pollution, `child_process` gadget.

## 3. Pwn / binary

```bash
checksec --file=bin
rabin2 -I bin
gdb -q bin -ex 'info functions' -ex 'checksec'
```

Workflow: identify vuln (overflow, format string, UAF, heap) → find offset (`pattern_create`/`pattern_offset`, cyclic) → control RIP → leak libc (`puts@plt`, `printf` format) → ret2libc / ROP (`ROPgadget`, `ropper`, `pwntools`) → shell.

```python
from pwn import *
elf = ELF('./bin'); libc = ELF('./libc.so.6')
p = process('./bin')          # or remote('host', port)
p.recvuntil(b'> ')
payload = flat({72: p64(elf.plt['puts']), 80: p64(elf.got['puts']), 88: p64(elf.symbols['main'])})
```

Topics: ret2win, ret2shellcode (NX off), ret2libc, ret2csu, SROP, format string write (`%n`), stack canary leak, PIE base leak, heap (tcache poisoning, fastbin dup, unsorted bin leak), FSOP, one_gadget, seccomp + ORW shellcode.

## 4. Reversing

```bash
ghidra                              # decompile
r2 -A bin; afl; pdf @ main; axt @ sym.imp.strcmp
objdump -d -M intel bin
# .NET
dnSpy / ilspycmd
# Python
uncompyle6 / decompyle3 / pycdc
# Java
jadx-gui app.apk
```

Patterns: flag comparison loop, XOR with key, RC4/AES with embedded key, base64 chains, VM-based checks, anti-debug, packed (UPX → `upx -d`).

`angr` for symbolic execution when the check is complex:
```python
import angr, claripy
p = angr.Project('./bin')
s = p.factory.entry_state()
sm = p.factory.simulation_manager(s)
sm.explore(find=0x401234, avoid=0x401000)
print(sm.found[0].posix.dumps(0))
```

## 5. Crypto

- RSA: small `e` (cube root), common modulus, Wiener (small `d`), Hastad broadcast, Fermat factorization (close primes), `gcd(n1,n2)` shared prime, `p`-1 smooth, Coppersmith (partial plaintext), Bleichenbacher (padding oracle).
- XOR: known plaintext, crib dragging, repeating-key analysis.
- Block ciphers: ECB pattern, CBC bit flipping, padding oracle, IV reuse, nonce reuse (GCM/CTR).
- Hashes: length extension, rainbow tables, `hashcat` modes, HMAC key recovery.
- Classical: frequency analysis, Vigenère, substitution (`quipqiup`).

```bash
python3 -c "from Crypto.Util.number import *; print(long_to_bytes(pow(c,d,n)))"
hashcat -m 0 hashes.txt rockyou.txt
rsactftool --publickey key.pub --uncipherfile cipher
```

## 6. Forensics

```bash
# Disk/memory
volatility3 -f mem.dmp windows.pslist
vol -f mem.dmp windows.cmdline
autopsy / sleuthkit: fls, icat, mmls
# Network
wireshark / tshark -r cap.pcap -Y http
tshark -r cap.pcap -T fields -e http.request.uri
# Images
zsteg img.png; steghide extract -sf img.jpg; stegsolve; pngcheck -v; exiftool
# Audio
audacity spectrogram; sonic-visualiser; sox
# Documents
oleid, olevba, pdf-parser, peepdf
# Archives
binwalk -eM; 7z x; john --format=zip2john
```

Look for: deleted files, alternate data streams, slack space, MFT, registry hives, browser history, USB history, prefetch, event logs, base64 in memory, encrypted ZIP with weak password.

## 7. Misc / jail

```bash
# Python jail
__builtins__; __import__('os').system('sh')
().__class__.__bases__[0].__subclasses__()
# filter bypass: chr(), getattr, string concat, globals()
# Bash jail
$0, ${PATH:0:1}, /???/???, $(<flag)
# Node jail
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('sh')
```

Esolangs: Brainfuck, Malbolge, Whitespace, Piet. OSINT: `exiftool`, `whois`, reverse image, geolocation, username enumeration (`sherlock`), Wayback.

## 8. Common flags & where they hide

- `/flag`, `/flag.txt`, `/root/flag`, env var, database row, DNS TXT, comment in source, EXIF, appended to image, in deleted partition, in memory dump, in HTTP response header, in JWT claim, in S3 bucket.

## 9. Tooling install

```bash
pip install pwntools angr z3-solver pycryptodome
sudo apt install gdb radare2 binwalk foremost exiftool steghide
# gef / pwndbg for gdb
```

## 10. Discipline

- Note every step; CTF writeups need the path, not just the flag.
- Automate repetition with pwntools templates.
- If stuck 20 minutes, switch category or re-read the description — the hint is usually there.
