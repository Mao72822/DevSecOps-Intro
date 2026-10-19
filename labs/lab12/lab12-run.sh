#!/usr/bin/env bash
# Lab 12 - Kata vs runc isolation. Run inside WSL2 (needs /dev/kvm, containerd, nerdctl).
#   cd /mnt/c/Users/mao72/PycharmProjects/DevSecOps-Intro
#   sudo bash labs/lab12/lab12-run.sh            # default Kata 4.1.0
#   sudo KATA_VER=4.1.0 bash labs/lab12/lab12-run.sh
# Every proof is written to labs/lab12/results/. Then tell Claude.
set -uo pipefail

KATA_VER="${KATA_VER:-4.1.0}"
IMG="alpine:3.20"
KATA="io.containerd.kata.v2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RES="$ROOT/labs/lab12/results"
mkdir -p "$RES"
LOG="$RES/run-log.txt"; : > "$LOG"
say(){ echo "## $*" | tee -a "$LOG" >&2; }
run(){ echo "### $*" >>"$LOG"; eval "$*" 2>&1 | tee -a "$LOG"; }
# strip CR so Windows line-endings in the repo scripts can't break bash
nocr(){ sed 's/\r$//' "$1"; }

if [ "$(id -u)" -ne 0 ]; then echo "Run with sudo." >&2; exit 1; fi

say "0. Prerequisites"
if ! ls -l /dev/kvm >>"$LOG" 2>&1; then echo "No /dev/kvm - Kata cannot run. Stop." | tee -a "$LOG" >&2; exit 1; fi
command -v containerd nerdctl >>"$LOG" 2>&1 || { echo "containerd/nerdctl missing" >&2; exit 1; }
{ echo "host-kernel: $(uname -r)"; uname -a; nerdctl version 2>/dev/null | head -20; containerd --version; } > "$RES/versions.txt"
uname -r > "$RES/host-kernel.txt"
nerdctl pull -q "$IMG" >>"$LOG" 2>&1

restart_containerd(){
  if [ -d /run/systemd/system ] && systemctl list-unit-files 2>/dev/null | grep -q '^containerd'; then
    systemctl restart containerd
  else
    pkill -x containerd 2>/dev/null || true; sleep 2
    nohup /usr/local/bin/containerd >/var/log/containerd.log 2>&1 &
  fi
  for i in $(seq 1 30); do nerdctl info >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

if [ "${SKIP_INSTALL:-0}" != 1 ]; then
  say "12.1 Install Kata $KATA_VER"
  nocr "$ROOT/labs/lab12/scripts/install-kata-assets.sh"      > /tmp/lab12-install.sh
  nocr "$ROOT/labs/lab12/scripts/configure-containerd-kata.sh" > /tmp/lab12-config.sh
  if [ ! -s /opt/kata/VERSION ]; then
    bash /tmp/lab12-install.sh "$KATA_VER" 2>&1 | tee -a "$LOG"
  else
    echo "Kata $(cat /opt/kata/VERSION) already installed; skipping the download" | tee -a "$LOG"
  fi
  bash /tmp/lab12-config.sh 2>&1 | tee -a "$LOG"
fi

# Wire up the shim + config regardless of SKIP_INSTALL. Kata 4.x (runtime-rs) keeps the
# shim under /opt/kata/runtime-rs/bin, and dragonball is built into it.
say "Wiring up Kata shim and config"
shim=$(find /opt/kata -type f -name 'containerd-shim-kata-v2' 2>/dev/null | head -1)
[ -n "$shim" ] && ln -sf "$shim" /usr/local/bin/containerd-shim-kata-v2
mkdir -p /etc/kata-containers
dbcfg=$(find /opt/kata/share/defaults -name 'configuration-dragonball.toml' 2>/dev/null | head -1)
[ -n "$dbcfg" ] && ln -sf "$dbcfg" /etc/kata-containers/configuration.toml
echo "shim -> ${shim:-NOT FOUND}; config -> ${dbcfg:-NOT FOUND}" | tee -a "$LOG"
say "Restarting containerd"
restart_containerd || echo "WARN: containerd did not answer after restart" | tee -a "$LOG" >&2

{ echo "== /opt/kata/VERSION"; cat /opt/kata/VERSION 2>/dev/null
  echo "== shim binary"; ls -l "${shim:-/nonexistent}" /usr/local/bin/containerd-shim-kata-v2 2>&1
  echo "== kata config in use"; ls -l /etc/kata-containers/configuration.toml 2>&1
  echo "== containerd config kata block"; grep -n -A2 -i 'runtimes.*kata\|kata' /etc/containerd/config.toml 2>/dev/null; } > "$RES/kata-config.txt"

say "Verify kata runtime works"
if nerdctl run --rm --runtime="$KATA" "$IMG" true >>"$LOG" 2>&1; then
  echo "kata OK" | tee -a "$LOG" >&2
else
  echo "KATA FAILED - capturing error + containerd log" | tee -a "$LOG" >&2
  { echo "== nerdctl run error =="; nerdctl run --rm --runtime="$KATA" "$IMG" uname -r 2>&1
    echo "== containerd log (last 80) =="
    journalctl -u containerd --no-pager -n 80 2>/dev/null || tail -n 80 /var/log/containerd.log 2>/dev/null
  } > "$RES/kata-error.txt" 2>&1 || true
fi

# ---------------------------------------------------------------- Task 1
say "12.2 Same command, two runtimes"
nerdctl run --rm "$IMG" uname -r | tee "$RES/runc-kernel.txt" | tee -a "$LOG"
nerdctl run --rm --runtime="$KATA" "$IMG" uname -r | tee "$RES/kata-kernel.txt" | tee -a "$LOG"
{
  echo "host   kernel: $(cat "$RES/host-kernel.txt")"
  echo "runc   kernel: $(cat "$RES/runc-kernel.txt" 2>/dev/null)"
  echo "kata   kernel: $(cat "$RES/kata-kernel.txt" 2>/dev/null)"
} > "$RES/kernels.txt"
{
  echo "device count (ls /dev | wc -l):"
  echo "  runc: $(nerdctl run --rm "$IMG" sh -c 'ls /dev | wc -l')"
  echo "  kata: $(nerdctl run --rm --runtime="$KATA" "$IMG" sh -c 'ls /dev | wc -l')"
} | tee "$RES/devices.txt" | tee -a "$LOG"
{
  echo "CapEff (unprivileged):"
  echo -n "  runc: "; nerdctl run --rm "$IMG" sh -c 'grep ^CapEff /proc/1/status' | awk '{print $2}'
  echo -n "  kata: "; nerdctl run --rm --runtime="$KATA" "$IMG" sh -c 'grep ^CapEff /proc/1/status' | awk '{print $2}'
} | tee "$RES/caps.txt" | tee -a "$LOG"

# ---------------------------------------------------------------- Task 2
say "12.3 Startup (warm-up thrown away, then 5 timed)"
median(){ printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
: > "$RES/startup.txt"
for rt in runc kata; do
  FLAG=""; [ "$rt" = kata ] && FLAG="--runtime=$KATA"
  nerdctl run --rm $FLAG "$IMG" true >/dev/null 2>&1   # warm-up
  times=()
  for i in 1 2 3 4 5; do
    t0=$(date +%s.%N); nerdctl run --rm $FLAG "$IMG" true >/dev/null 2>&1; t1=$(date +%s.%N)
    e=$(awk "BEGIN{printf \"%.2f\", $t1-$t0}"); times+=("$e")
  done
  echo "== $rt startup (s): ${times[*]}  median=$(median "${times[@]}")" | tee -a "$RES/startup.txt" "$LOG"
done

say "I/O (write 512 MiB to the container fs with fsync)"
: > "$RES/io.txt"
for rt in runc kata; do
  FLAG=""; [ "$rt" = kata ] && FLAG="--runtime=$KATA"
  echo "== $rt io ==" | tee -a "$RES/io.txt" "$LOG"
  nerdctl run --rm $FLAG "$IMG" sh -c 'dd if=/dev/zero of=/tmp/bench bs=1M count=512 conv=fsync 2>&1 | tail -1' | tee -a "$RES/io.txt" "$LOG"
done

say "Memory overhead per container (MemAvailable delta + VMM RSS)"
: > "$RES/memory.txt"
for rt in runc kata; do
  FLAG=""; [ "$rt" = kata ] && FLAG="--runtime=$KATA"
  sync; a0=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  cid=$(nerdctl run -d $FLAG "$IMG" sleep 120 2>>"$LOG")
  sleep 8
  a1=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
  delta_mib=$(( (a0 - a1) / 1024 ))
  vmm=$(ps -eo rss,comm,args 2>/dev/null | grep -iE 'qemu|dragonball|cloud-hypervisor|kata' | grep -v grep | awk '{s+=$1} END{printf "%d", s/1024}')
  echo "== $rt: MemAvailable delta = ${delta_mib} MiB; kata VMM/shim RSS sum = ${vmm:-0} MiB" | tee -a "$RES/memory.txt" "$LOG"
  nerdctl rm -f "$cid" >>"$LOG" 2>&1
  sleep 2
done

# ---------------------------------------------------------------- Bonus escape
say "12.4/12.5 Privileged + host bind mount escape, both runtimes"
: > "$RES/escape.txt"
for rt in runc kata; do
  FLAG=""; [ "$rt" = kata ] && FLAG="--runtime=$KATA"
  echo "original" > /tmp/lab12-target
  before=$(cat /tmp/lab12-target)
  out=$(nerdctl run --rm --privileged -v /tmp:/host_tmp $FLAG "$IMG" \
          sh -c 'echo "OVERWRITTEN" > /host_tmp/lab12-target; echo "wrote from inside $(uname -r)"' 2>&1)
  after=$(cat /tmp/lab12-target)
  {
    echo "== $rt =="
    echo "  container said: $out"
    echo "  host /tmp/lab12-target BEFORE: $before"
    echo "  host /tmp/lab12-target AFTER : $after"
    if [ "$after" = "OVERWRITTEN" ]; then echo "  => HOST FILE MODIFIED (escape succeeded)"; else echo "  => host file intact (contained)"; fi
  } | tee -a "$RES/escape.txt" "$LOG"
  echo "original" > /tmp/lab12-target
done

say "Privileged device count + cap mask, both runtimes"
: > "$RES/priv-devices-caps.txt"
for rt in runc kata; do
  FLAG=""; [ "$rt" = kata ] && FLAG="--runtime=$KATA"
  line=$(nerdctl run --rm --privileged $FLAG "$IMG" sh -c 'echo "devices=$(ls /dev | wc -l) $(grep ^CapEff /proc/1/status)"')
  echo "== $rt privileged: $line" | tee -a "$RES/priv-devices-caps.txt" "$LOG"
done

echo "DONE" | tee -a "$LOG" >&2
echo "Results in labs/lab12/results/. Tell Claude." >&2
echo "Undo later: edit /etc/containerd/config.toml (remove kata block), restart containerd, rm -rf /opt/kata" >&2
