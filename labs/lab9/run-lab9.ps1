# Lab 9 - Falco part (needs Docker Desktop / WSL2 on this PC).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File labs\lab9\run-lab9.ps1
# (or double-click labs\lab9\run-lab9.bat)
# Output goes to labs\lab9\falco\logs\ (gitignored); Claude fills submissions\lab9.md from it.
$ErrorActionPreference = "Continue"
# Falco 0.43.1 (the lab's version) hangs in the kernel (register_kprobe, state D) while
# attaching its modern eBPF probe on Docker Desktop's WSL2 6.6 kernel; 0.39.2 predates those
# probe changes. Override:  run-lab9.bat 0.43.1
$FalcoVer = if ($args.Count -gt 0 -and $args[0]) { $args[0] } else { "0.39.2" }
# older releases: the -no-driver image has the modern eBPF probe built in and no driver-loader entrypoint
$FalcoImg = if ($FalcoVer -like "0.4[3-9]*") { "falcosecurity/falco:$FalcoVer" } else { "falcosecurity/falco-no-driver:$FalcoVer" }
Write-Host "Using $FalcoImg"
$L = "labs/lab9/falco/logs"
New-Item -ItemType Directory -Force $L, "labs/lab9/falco/rules" | Out-Null
$log = "$L/run-log.txt"
Remove-Item $log, "$L/falco-*.log" -ErrorAction SilentlyContinue
function Log($name, [scriptblock]$cmd) { "### $name" | Out-File -Append -Encoding utf8 $log; & $cmd 2>&1 | ForEach-Object { "$_" } | Tee-Object -Variable out | Out-File -Append -Encoding utf8 $log; $out }
function Snap($tag) { cmd /c "docker logs falco > $L\falco-$tag.log 2>&1" }

Log "versions" { "falco image: $FalcoImg"; docker --version; docker version --format "server {{.Server.Version}} / {{.Server.KernelVersion}}" }

# fresh start
Write-Host "Removing old containers (may take a minute if an old Falco is stuck)..."
docker rm -f falco lab9-target *> $null

# --- images: Docker Hub may be unreachable from here, so try mirrors of the same images
# and tag the result with the name the lab uses.
function Get-Image($want, [string[]]$sources) {
  docker image inspect $want *> $null
  if ($LASTEXITCODE -eq 0) { "have $want"; return $true }
  foreach ($src in $sources) {
    for ($try = 1; $try -le 2; $try++) {
      Write-Host "Pulling $src (attempt $try)..."
      docker pull $src 2>&1 | Select-Object -Last 2 | ForEach-Object { "$_" }
      if ($LASTEXITCODE -eq 0) {
        if ($src -ne $want) { docker tag $src $want }
        "using $src as $want"; return $true
      }
    }
  }
  return $false
}
$ok1 = Log "pull falco" { Get-Image $FalcoImg @($FalcoImg,"public.ecr.aws/$FalcoImg","mirror.gcr.io/$FalcoImg") }
$ok2 = Log "pull alpine" { Get-Image "alpine:3.20" @("alpine:3.20","public.ecr.aws/docker/library/alpine:3.20","mirror.gcr.io/library/alpine:3.20") }
if (-not (docker image inspect $FalcoImg 2>$null) -or -not (docker image inspect alpine:3.20 2>$null)) {
  Write-Host "Could not download the images from Docker Hub or any mirror. Turn on your VPN and run this again." -ForegroundColor Red
  exit 1
}

# --- 9.1 Falco + target ---
$rules = (Resolve-Path "labs/lab9/falco/rules").Path
Log "9.1 start falco" {
  docker run -d --name falco --privileged `
    -v /proc:/host/proc:ro -v /boot:/host/boot:ro `
    -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro `
    -v /var/run/docker.sock:/host/var/run/docker.sock `
    -v "${rules}:/etc/falco/rules.d:ro" `
    $FalcoImg `
    falco -U -o engine.kind=modern_ebpf -o json_output=true -o time_format_iso_8601=true `
    -o metrics.enabled=true -o metrics.interval=10s -o metrics.output_rule=true
}
Log "9.1 start target" { docker run -d --name lab9-target alpine:3.20 sleep 1d }
# On the WSL2 kernel attaching the modern eBPF probe takes minutes (kernel thread sits in
# register_kprobe). Falco is only listening once its periodic metrics snapshot appears.
function Count-Text($text) { (cmd /c "docker logs falco 2>&1" | Select-String -SimpleMatch $text).Count }
function Wait-Ready($opensBefore) {
  $t0 = Get-Date
  # wait until Falco has (re)opened the syscall source ...
  while ((Count-Text "Opening 'syscall' source") -le $opensBefore) {
    if (((Get-Date) - $t0).TotalSeconds -gt 300) { return $false }; Start-Sleep 5 }
  # ... and then emitted a metrics snapshot after that
  $m0 = Count-Text "Falco internal: metrics snapshot"
  while ((Count-Text "Falco internal: metrics snapshot") -le $m0) {
    $s = [int]((Get-Date) - $t0).TotalSeconds
    Write-Host "  waiting for Falco to attach its probe... ${s}s"
    if ($s -gt 300) { return $false }; Start-Sleep 10 }
  "ready after $([int]((Get-Date) - $t0).TotalSeconds)s"; return $true
}
Write-Host "Waiting for Falco to become ready (can take several minutes on WSL2)..."
$ready = Log "9.1 wait ready" { Wait-Ready 0 }
if (-not ($ready -contains "True")) { Write-Host "Falco $FalcoVer did not attach its probe within 5 min. Close this window, run  wsl --shutdown , start Docker Desktop and tell Claude." -ForegroundColor Red; Snap "startup"; exit 1 }
Log "9.1 falco state" { docker ps -a --filter name=falco --format "{{.Names}} {{.Status}}" }
Log "9.1 falco startup (tail)" { docker logs falco 2>&1 | Select-Object -Last 15 }
Snap "startup"
$state = docker inspect -f "{{.State.Running}}" falco
if ($state -ne "true") { Write-Host "Falco is not running - see $L\falco-startup.log. Send it to Claude." -ForegroundColor Red; exit 1 }

# --- 9.2 built-in rules ---
Log "9.2 shell with tty" { docker exec -t lab9-target sh -lc 'echo hello-from-shell' }
Log "9.2 read shadow"    { docker exec lab9-target sh -c 'cat /etc/shadow' }
Start-Sleep 15
Log "9.2 rule counts" { docker logs falco 2>&1 | Select-String -Pattern '"rule":"[^"]*"' -AllMatches | ForEach-Object { $_.Matches.Value } | Group-Object | ForEach-Object { "{0,5} {1}" -f $_.Count, $_.Name } }
Snap "after-9.2"

# --- 9.3 custom rule (reload with SIGHUP) ---
Log "9.3 write to /tmp" { docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt' }
Start-Sleep 15
Log "9.3 count custom rule" { (docker logs falco 2>&1 | Select-String -SimpleMatch '"rule":"Write Below Tmp In Container"').Count }
Snap "after-9.3"

# --- Bonus: cryptominer (refused connection to local port 3333; no real pool) ---
Log "bonus nc to 3333" { docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'; "nc exit=$LASTEXITCODE" }
Start-Sleep 15
Log "bonus count critical" { (docker logs falco 2>&1 | Select-String -SimpleMatch '"priority":"Critical"').Count }
Log "final rule counts" { docker logs falco 2>&1 | Select-String -Pattern '"rule":"[^"]*"' -AllMatches | ForEach-Object { $_.Matches.Value } | Group-Object | ForEach-Object { "{0,5} {1}" -f $_.Count, $_.Name } }
Snap "final"

# --- SIGHUP reload (lab 9.3 step), done last: rules were already loaded at start, and on
# this kernel re-attaching the probe can hang, which must not cost us the alerts above.
$opens = Count-Text "Opening 'syscall' source"
Log "9.3 reload" { docker kill --signal=SIGHUP falco }
Write-Host "Waiting for Falco to reload (up to 5 min)..."
Log "9.3 wait ready after reload" { Wait-Ready $opens }
Log "9.3 falco reload messages" { docker logs falco 2>&1 | Select-Object -Last 10 }
Log "after reload: shell again" { docker exec -t lab9-target sh -lc 'echo after-reload' }
Start-Sleep 15
Log "rule counts after reload" { docker logs falco 2>&1 | Select-String -Pattern '"rule":"[^"]*"' -AllMatches | ForEach-Object { $_.Matches.Value } | Group-Object | ForEach-Object { "{0,5} {1}" -f $_.Count, $_.Name } }
Snap "after-reload"

# conftest, if installed here (Claude already ran it; this is just a cross-check)
if (Get-Command conftest -ErrorAction SilentlyContinue) {
  Log "conftest version" { conftest --version }
  foreach ($f in "labs/lab9/manifests/k8s/juice-hardened.yaml","labs/lab9/manifests/k8s/juice-violates-extra.yaml","labs/lab9/manifests/k8s/juice-unhardened.yaml","labs/lab9/manifests/compose/juice-compose.yml") {
    Log "conftest $f" { conftest test $f --policy labs/lab9/policies --all-namespaces --no-color }
  }
}

"DONE" | Out-File -Append -Encoding utf8 $log
Write-Host "Done. Tell Claude to finish the write-up. Clean up later with: docker rm -f falco lab9-target" -ForegroundColor Green
