# Environment Setup

Bring a fresh Kali box to a working offensive platform in under 30 minutes.

## 1. Base packages

```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install \
  nmap masscan netcat-traditional socat proxychains4 tmux jq curl wget git \
  python3-pip pipx golang-go build-essential gcc g++ make \
  seclists wordlists dirb gobuster ffuf feroxbuster whatweb nikto sqlmap \
  hydra john hashcat smbclient smbmap enum4linux-ng ldap-utils nfs-common \
  responder wireshark tcpdump aircrack-ng bettercap \
  binwalk foremost exiftool steghide gdb radare2 \
  impacket-scripts bloodhound neo4j certipy-ad netexec \
  openvpn freerdp3-x11
```

## 2. Go tools

```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/owasp-amass/amass/v4/...@master
```

## 3. Python tools

```bash
pipx install impacket
pipx install bloodhound
pipx install certipy-ad
pipx install netexec
pipx install pwncat-cs
pipx install shodan
pipx install pycryptodome
pipx install pwntools
pipx install angr
pipx install pyyaml
```

## 4. Content

```bash
nuclei -update-templates
git clone --depth 1 https://github.com/danielmiessler/SecLists ~/tools/SecLists
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings ~/tools/PayloadsAllTheThings
git clone --depth 1 https://github.com/GTFOBins/GTFOBins.github.io ~/tools/GTFOBins
git clone --depth 1 https://github.com/peass-ng/PEASS-ng ~/tools/PEASS
```

## 5. Proxy and browser

- Burp Suite Community or Caido; export CA, import into Firefox and Chrome.
- FoxyProxy profile: `127.0.0.1:8080`, all URLs.
- Disable browser telemetry and update checks; use a dedicated profile per engagement.

## 6. Shell and tmux

```bash
# ~/.zshrc or ~/.bashrc
alias ll='ls -lah'
alias nse='ls /usr/share/nmap/scripts | grep'
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:$HOME/.local/bin
setopt hist_ignore_space      # zsh: no history for commands starting with space
```

tmux layout for an engagement:

```
┌──────────────┬──────────────┐
│ recon        │ exploitation │
├──────────────┼──────────────┤
│ notes        │ listener     │
└──────────────┴──────────────┘
```

`tmux new -s eng`, `Ctrl-b %`, `Ctrl-b "`, `Ctrl-b d`. Always work inside a session — a dropped SSH connection should not kill a scan.

## 7. Directory layout

```
~/engagements/<target>-<date>/
├── scope.md
├── state.md
├── coverage.md
├── assets.txt
├── ports.json
├── hypotheses.md
├── findings.yaml
├── progress.log
├── poc/F-01/...
├── recon/
└── report/
```

`git init` in the engagement dir. Commit after every finding — tamper-evident timeline for free.

## 8. Logging wrapper

```bash
# ~/bin/logrun — timestamp every command
#!/usr/bin/env bash
LOG="${ENGAGEMENT_LOG:-./progress.log}"
printf '\n[%s] $ %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"
"$@" 2>&1 | tee -a "$LOG"
```

`chmod +x ~/bin/logrun` and use `logrun nmap -sV target` for anything you may need to cite later.

## 9. VPN / connectivity

```bash
sudo openvpn --config client.ovpn --daemon
ip a show tun0
# verify routing to the target network before scanning
ip route get 10.10.10.10
```

## 10. C2 (lab / authorized RT only)

```bash
# Sliver
curl https://sliver.sh/install | sudo bash
sliver-server

# Mythic
sudo ./install_docker_ubuntu.sh && sudo ./mythic-cli install github https://github.com/its-a-feature/Mythic
```

Keep C2 infrastructure on separate hosts from the testing workstation. Never host C2 on the same VPS as the phishing domain.

## 11. Sanity check

```bash
nmap --version; nuclei -version; nxc --version; certipy --version
ffuf -V; sqlmap --version; hashcat --version
curl -s https://api.ipify.org; echo
```

All tools resolve, proxy intercepts, VPN routes. You are ready.
