#!/usr/bin/env bash
# Lab 12 prep for Ubuntu (WSL2): containerd + nerdctl + runc + CNI + deps.
#   sudo bash labs/lab12/setup-wsl.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash labs/lab12/setup-wsl.sh" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "== apt deps =="
apt-get update
apt-get install -y curl ca-certificates zstd jq iptables uidmap

if ! command -v nerdctl >/dev/null 2>&1; then
  NERDCTL_VER="${NERDCTL_VER:-}"
  if [ -z "$NERDCTL_VER" ]; then
    NERDCTL_VER=$(curl -fsSL https://api.github.com/repos/containerd/nerdctl/releases/latest \
      | grep -oP '"tag_name":\s*"v\K[^"]+' | head -1 || true)
  fi
  [ -z "$NERDCTL_VER" ] && NERDCTL_VER=2.0.3
  echo "== installing nerdctl-full $NERDCTL_VER =="
  TB="nerdctl-full-${NERDCTL_VER}-linux-amd64.tar.gz"
  tmp=$(mktemp -d)
  curl -fL -o "$tmp/$TB" "https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VER}/${TB}"
  tar -C /usr/local -xzf "$tmp/$TB"
  rm -rf "$tmp"
else
  echo "nerdctl already present: $(command -v nerdctl)"
fi

echo "== starting containerd =="
if [ -d /run/systemd/system ]; then
  cp -f /usr/local/lib/systemd/system/containerd.service /etc/systemd/system/containerd.service 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable --now containerd
else
  if ! pgrep -x containerd >/dev/null 2>&1; then
    nohup /usr/local/bin/containerd >/var/log/containerd.log 2>&1 &
  fi
fi
for i in $(seq 1 30); do nerdctl info >/dev/null 2>&1 && break; sleep 1; done

echo "== versions =="
containerd --version || true
nerdctl version || true
runc --version || true
echo "== /dev/kvm =="; ls -l /dev/kvm || true
echo
if nerdctl run --rm alpine:3.20 true >/dev/null 2>&1; then
  echo "SETUP OK. Next:  sudo bash labs/lab12/lab12-run.sh"
else
  echo "containerd is up but a test 'nerdctl run' failed - send Claude the output of:"
  echo "  sudo nerdctl run --rm alpine:3.20 uname -r"
fi
