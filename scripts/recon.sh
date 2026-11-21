#!/usr/bin/env bash
# recon.sh — external asset discovery pipeline
# usage: ./recon.sh <domain> [outdir]
# Each stage is skippable: a missing tool is reported, not fatal.

set -uo pipefail

DOMAIN="${1:?usage: recon.sh <domain> [outdir]}"
OUT="${2:-./recon-$DOMAIN}"
mkdir -p "$OUT"/{subs,http,nuclei,raw}

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

log "target=$DOMAIN out=$OUT"

# ---------------------------------------------------------------- 1. passive subs
: > "$OUT/subs/passive.txt"
if have subfinder; then
  subfinder -d "$DOMAIN" -all -recursive -silent 2>/dev/null | tee -a "$OUT/subs/passive.txt" >/dev/null
  log "subfinder done: $(wc -l < "$OUT/subs/passive.txt")"
else log "skip subfinder (not installed)"; fi

if have assetfinder; then
  assetfinder --subs-only "$DOMAIN" 2>/dev/null | tee -a "$OUT/subs/passive.txt" >/dev/null
  log "assetfinder done"
fi

# certificate transparency
curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//' | tr ',' '\n' \
  | tee -a "$OUT/subs/passive.txt" >/dev/null
log "crtsh done"

sort -u "$OUT/subs/passive.txt" | grep -E "\.${DOMAIN//./\\.}$" > "$OUT/subs/all.txt"
log "unique subs: $(wc -l < "$OUT/subs/all.txt")"

# ---------------------------------------------------------------- 2. resolve
if have dnsx; then
  dnsx -l "$OUT/subs/all.txt" -silent -a -resp -o "$OUT/subs/resolved.txt" 2>/dev/null
  log "resolved: $(wc -l < "$OUT/subs/resolved.txt" 2>/dev/null || echo 0)"
else
  cp "$OUT/subs/all.txt" "$OUT/subs/resolved.txt"
  log "skip dnsx"
fi

# ---------------------------------------------------------------- 3. http probe
if have httpx; then
  httpx -l "$OUT/subs/resolved.txt" -silent \
    -status-code -title -tech-detect -web-server -follow-redirects \
    -o "$OUT/http/live.txt" 2>/dev/null
  log "live: $(wc -l < "$OUT/http/live.txt" 2>/dev/null || echo 0)"
else
  log "skip httpx"
fi

# ---------------------------------------------------------------- 4. ports
if have naabu && [[ -s "$OUT/subs/resolved.txt" ]]; then
  naabu -l "$OUT/subs/resolved.txt" -silent -top-ports 1000 -rate 1000 \
    -o "$OUT/raw/ports.txt" 2>/dev/null
  log "open ports: $(wc -l < "$OUT/raw/ports.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------- 5. urls
if have gau; then
  gau --subs "$DOMAIN" 2>/dev/null > "$OUT/raw/gau.txt"
  log "gau urls: $(wc -l < "$OUT/raw/gau.txt")"
fi
if have waybackurls; then
  waybackurls "$DOMAIN" 2>/dev/null > "$OUT/raw/wayback.txt"
  log "wayback urls: $(wc -l < "$OUT/raw/wayback.txt")"
fi

# ---------------------------------------------------------------- 6. tech/cve scan
if have nuclei && [[ -s "$OUT/http/live.txt" ]]; then
  nuclei -l "$OUT/http/live.txt" -tags tech,exposure,config,misconfig \
    -severity info,low,medium -rl 30 -silent \
    -o "$OUT/nuclei/tech.txt" 2>/dev/null
  log "nuclei tech findings: $(wc -l < "$OUT/nuclei/tech.txt" 2>/dev/null || echo 0)"
fi

# ---------------------------------------------------------------- 7. screenshots
if have gowitness && [[ -s "$OUT/http/live.txt" ]]; then
  gowitness scan file -f "$OUT/http/live.txt" --screenshot-path "$OUT/http/shots" \
    >/dev/null 2>&1 && log "screenshots saved"
fi

log "done -> $OUT"
cat <<EOF

Next:
  1. Review $OUT/http/live.txt and $OUT/nuclei/tech.txt
  2. Import $OUT/raw/ports.txt into nmap: nmap -sV -sC -p <ports> -iL hosts
  3. Create engagements/<target>/ and copy outputs there
  4. Update coverage.md
EOF
