# Lab 9 final check of custom-rules.yaml: /tmp write, bonus rule on refused and accepted nc -> :3333
$ErrorActionPreference = "Continue"
$L = "labs/lab9/falco/logs"; $out = "$L/final-check.txt"
Remove-Item $out -ErrorAction SilentlyContinue
function D($name, [scriptblock]$cmd) { "### $name" | Out-File -Append -Encoding utf8 $out; & $cmd 2>&1 | ForEach-Object { "$_" } | Out-File -Append -Encoding utf8 $out }
$img = "falcosecurity/falco-no-driver:0.39.2"
docker rm -f falco-bonus *> $null
docker start lab9-target *> $null
# rules dir copied into a temp dir together with the debug rule
$tmp = Join-Path $env:TEMP "lab9-rules"; Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory $tmp | Out-Null
Copy-Item labs/lab9/falco/rules/*.yaml $tmp
D "start" { docker run -d --name falco-bonus --privileged `
  -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro `
  -v /var/run/docker.sock:/host/var/run/docker.sock -v "${tmp}:/etc/falco/rules.d:ro" `
  $img falco -U -o engine.kind=modern_ebpf -o json_output=true -o time_format_iso_8601=true }
Write-Host "waiting 25s for Falco..."; Start-Sleep 25
D "write /tmp" { docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt' }
D "refused: nc -w 2 127.0.0.1 3333" { docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'; "exit=$LASTEXITCODE" }
Start-Sleep 3
docker exec -d lab9-target sh -c 'nc -l -p 3333 > /dev/null'
Start-Sleep 2
D "accepted: echo hi | nc -w 2 127.0.0.1 3333" { docker exec lab9-target sh -c 'echo hi | nc -w 2 127.0.0.1 3333'; "exit=$LASTEXITCODE" }
Start-Sleep 10
cmd /c "docker logs falco-bonus > $L\final-check-falco.log 2>&1"
D "rule counts" { cmd /c "docker logs falco-bonus 2>nul" | Select-String -Pattern '"rule":"[^"]*"' -AllMatches | ForEach-Object { $_.Matches.Value } | Group-Object | ForEach-Object { "{0,5} {1}" -f $_.Count, $_.Name } }
D "alerts" { cmd /c "docker logs falco-bonus 2>nul" }
docker rm -f falco-bonus *> $null
"DONE" | Out-File -Append -Encoding utf8 $out
Write-Host "Done. Tell Claude." -ForegroundColor Green
