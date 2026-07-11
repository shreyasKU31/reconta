#!/usr/bin/env bash
#
# modules/ports.sh — port & service discovery on resolved hosts.
# naabu finds open ports fast; nmap adds service/version depth on just those.
#
# Inputs : $OUTDIR/subdomains.txt
# Output : $OUTDIR/ports.txt   (host:port  →  service/version, one per line)

module_ports() {
  [[ "$ENABLE_PORTS" == 1 ]] || { log_info "ports: disabled"; return 0; }
  log_step "Ports & services"
  local resolved="$OUTDIR/subdomains.txt"
  local out="$OUTDIR/ports.txt"; touchf "$out"
  local naabu_out="$D_PORTS/naabu.txt"; mkdir -p "$D_PORTS"

  if [[ ! -s "$resolved" ]]; then log_warn "no hosts to scan"; return 0; fi
  require_tool naabu "port scan" || return 0

  # Port breadth scales with profile.
  local port_args=(-top-ports "$NAABU_TOP_PORTS")
  case "$PROFILE" in
    quick) port_args=(-top-ports 100) ;;
    deep)  port_args=(-p -) ;;          # full 65535
  esac

  log_info "naabu scan (${PROFILE} profile)…"
  naabu -l "$resolved" "${port_args[@]}" -rate "$RATE_LIMIT" -silent \
        -o "$naabu_out" >/dev/null 2>&1 || true
  log_result "$(count "$naabu_out") open host:port pairs"

  if [[ ! -s "$naabu_out" ]]; then
    log_ok "No open ports found"
    return 0
  fi

  # nmap service/version scan, targeted only at the ports naabu confirmed open.
  if have_tool nmap; then
    log_info "nmap service/version on open ports…"
    # Build a unique host list + the exact ports naabu saw for -p.
    local hlist="$D_PORTS/hosts.txt" plist
    cut -d: -f1 "$naabu_out" | sort -u > "$hlist"
    plist=$(cut -d: -f2 "$naabu_out" | sort -un | paste -sd, -)
    capped 900 nmap -sV -T4 --open -Pn -p "$plist" -iL "$hlist" \
      -oG "$D_PORTS/nmap.gnmap" >/dev/null 2>&1 || true

    if [[ -s "$D_PORTS/nmap.gnmap" ]]; then
      # Flatten grepable nmap into "host:port  service/version" lines.
      awk '/Ports:/{
        host=$2;
        n=split($0, a, "Ports: "); split(a[2], ports, ", ");
        for(i in ports){
          split(ports[i], f, "/");
          if(f[2]=="open"){
            svc=f[5]; ver=f[7]; gsub(/^ +| +$/,"",svc); gsub(/^ +| +$/,"",ver);
            printf "%s:%s\t%s %s\n", host, f[1], svc, ver
          }
        }
      }' "$D_PORTS/nmap.gnmap" | sort -u > "$out"
    fi
  fi

  # Fall back to the bare naabu list if nmap produced nothing.
  [[ -s "$out" ]] || cp "$naabu_out" "$out"
  log_ok "Ports/services mapped: $(count "$out")"
}
