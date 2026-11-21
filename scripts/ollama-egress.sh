#!/usr/bin/env bash
set -euo pipefail

# Manage systemd egress lockdown for ollama.service.
# Locked state blocks all outbound network access (IPAddressDeny=any, IPAddressAllow=localhost).
# Temporarily unlock only when pulling new models, then re-lock immediately.

DROPIN="/etc/systemd/system/ollama.service.d/20-egress-lock.conf"

case "${1:-status}" in
  status)
    if [[ -f "$DROPIN" ]]; then
      echo "Ollama egress: LOCKED ($DROPIN present)"
      cat "$DROPIN"
    else
      echo "Ollama egress: UNLOCKED ($DROPIN not present)"
    fi
    systemctl is-active ollama.service
    ;;
  lock)
    sudo mkdir -p /etc/systemd/system/ollama.service.d
    sudo tee "$DROPIN" >/dev/null <<'EOF'
[Service]
IPAddressDeny=any
IPAddressAllow=localhost
EOF
    sudo systemctl daemon-reload
    sudo systemctl restart ollama.service
    echo "Ollama egress LOCKED (localhost only)."
    ;;
  unlock)
    sudo rm -f "$DROPIN"
    sudo systemctl daemon-reload
    sudo systemctl restart ollama.service
    echo "Ollama egress UNLOCKED for model pulls. Run '$(basename "$0") lock' when done."
    ;;
  *)
    echo "Usage: $(basename "$0") [status|lock|unlock]" >&2
    exit 1
    ;;
esac
