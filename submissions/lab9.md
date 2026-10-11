# Lab 9 — Runtime Detection and Policy as Code

Files in this PR:

- `labs/lab9/falco/rules/custom-rules.yaml` — Task 1 rule (`Write Below Tmp In Container`) and Bonus rule (`Possible Cryptominer Pool Connection`)
- `labs/lab9/policies/extra/hardening.rego` — Task 2 deny + warn rules
- `labs/lab9/manifests/k8s/juice-violates-extra.yaml` — manifest written to violate them
- `labs/lab9/run-lab9.ps1` / `.bat` — runs 9.1–9.3 on Windows + Docker Desktop (WSL2): waits until the probe is attached (metrics snapshot), triggers the events, SIGHUP-reloads, saves logs to `labs/lab9/falco/logs/` (gitignored)
- `labs/lab9/falco-bonus.ps1` / `.bat` — final check of the rule file: `/tmp` write + refused and accepted `nc` to `:3333`

Environment: Windows + Docker Desktop 29.8.2 (WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`), Conftest 0.69.0.

**Falco version deviation.** The lab pins `falcosecurity/falco:0.43.1`. On this kernel 0.43.1 never finishes attaching its modern eBPF probe: the main thread sits in the kernel in `register_kprobe` in state `D` (uninterruptible), the process uses ~1 s of CPU in 14 min, no metrics snapshot is ever emitted and no alert ever fires; the container cannot even be removed until the WSL VM is restarted (`wsl --shutdown`). Diagnosis (from `/proc/1/task/*/wchan` inside the container):

```
falco
register_kprobe
State:	D (disk sleep)
falco
futex_wait_queue
State:	S (sleeping)
...
```

`falcosecurity/falco-no-driver:0.39.2` (same modern eBPF engine, older probe without the 0.41+ attach changes) attaches in ~10 s on the same kernel, so all Falco evidence below comes from **Falco 0.39.2**. The rules are written for both: nothing in them is version-specific, and they load without errors on 0.43.1 as well (`/etc/falco/rules.d/custom-rules.yaml | schema validation: ok`).

## Task 1 — Runtime detection with Falco

### 9.1 Falco start

```
docker run -d --name falco --privileged \
  -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v "$(pwd)/labs/lab9/falco/rules":/etc/falco/rules.d:ro \
  falcosecurity/falco-no-driver:0.39.2 \
  falco -U -o engine.kind=modern_ebpf -o json_output=true -o time_format_iso_8601=true \
        -o metrics.enabled=true -o metrics.interval=10s -o metrics.output_rule=true
```

(The metrics snapshot is how `labs/lab9/run-lab9.ps1` knows the probe is attached before it triggers anything.)

```
Falco version: 0.39.2 (x86_64)
System info: Linux version 6.6.87.2-microsoft-standard-WSL2 ...
Loading rules from:
   /etc/falco/falco_rules.yaml | schema validation: ok
   /etc/falco/falco_rules.local.yaml | schema validation: none
   /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
Opening 'syscall' source with modern BPF probe.
One ring buffer every '2' CPUs.
$ docker ps --filter name=falco
falco Up 10 seconds
```

### 9.2 Built-in rules

```
$ docker exec -t lab9-target sh -lc 'echo hello-from-shell'
$ docker exec lab9-target sh -c 'cat /etc/shadow'
$ docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
    1 "rule":"Read sensitive file untrusted"
    1 "rule":"Terminal shell in container"
```

(plus `Falco internal: metrics snapshot` lines from the metrics option, not counted).

**1. `Terminal shell in container` (Notice)** — triggered by `docker exec -t ... sh -lc`: an `execve` of a shell (`proc.name=sh`) inside a container with a TTY attached (`proc.tty=34816`). Without `-t` the same command has `proc.tty=0` and the rule stays silent.

```
2026-10-11T22:40:21.749337420+0000: Notice A shell was spawned in a container with an attached terminal (evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA> command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=563750fc637c container_name=lab9-target)
```

**2. `Read sensitive file untrusted` (Warning)** — triggered by `cat /etc/shadow`: an `open` for reading of a file in the `sensitive_files` list by a process (`cat`) that is not on the trusted-reader list (login, sshd, PAM tooling...). No TTY needed.

```
2026-10-11T22:40:21.839915665+0000: Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow gparent=<NA> ggparent=<NA> gggparent=<NA> evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=<NA> command=cat /etc/shadow terminal=0 container_id=563750fc637c container_name=lab9-target)
```

### 9.3 Custom rule

```yaml
- rule: Write Below Tmp In Container
  desc: >
    A process inside a container (not on the host) opened a file under /tmp/
    for writing. /tmp is the usual drop zone for downloaded payloads and
    scripts, so a write there is a sign of container drift.
  condition: >
    open_write
    and container.id != host
    and container.id != ""
    and not proc.name startswith "runc"
    and fd.name startswith /tmp/
  output: >
    File below /tmp opened for writing in container
    (container=%container.name container_id=%container.id image=%container.image.repository
    user=%user.name uid=%user.uid file=%fd.name cmdline=%proc.cmdline
    parent=%proc.pname)
  priority: WARNING
  tags: [container, drift]
```

- `open_write` is the shipped macro (`evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0`), so only successful opens of regular files for writing count.
- `container.id != host` drops everything that happens on the host itself.
- `container.id != ""` and `not proc.name startswith "runc"` were added after the first run: see the runc alert below.
- `fd.name startswith /tmp/` — the trailing slash keeps `/tmpfoo` out.

Trigger and count:

```
$ docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
$ docker logs falco 2>&1 | grep -c '"rule":"Write Below Tmp In Container"'
2
```

The alert for my write:

```json
{
  "hostname": "1487a13d88ef",
  "output": "2026-10-11T22:40:37.121874139+0000: Warning File below /tmp opened for writing in container (container=lab9-target container_id=563750fc637c image=alpine user=root uid=0 file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt parent=<NA>)",
  "output_fields": {
    "container.id": "563750fc637c",
    "container.image.repository": "alpine",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791758437121874139,
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.pname": null,
    "user.name": "root",
    "user.uid": 0
  },
  "priority": "Warning",
  "rule": "Write Below Tmp In Container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-10-11T22:40:37.121874139Z"
}
```

The second hit was not mine:

```json
{
  "hostname": "1487a13d88ef",
  "output": "2026-10-11T22:40:37.097375983+0000: Warning File below /tmp opened for writing in container (container=<NA> container_id= image=<NA> user=<NA> uid=4294967295 file=/tmp/runc-process3565819325 cmdline=<NA> parent=<NA>)",
  "output_fields": {
    "container.id": "",
    "container.image.repository": null,
    "container.name": null,
    "evt.time.iso8601": 1791758437097375983,
    "fd.name": "/tmp/runc-process3565819325",
    "proc.cmdline": "<NA>",
    "proc.pname": null,
    "user.name": "<NA>",
    "user.uid": 4294967295
  },
  "priority": "Warning",
  "rule": "Write Below Tmp In Container",
  "source": "syscall",
  "tags": [
    "container",
    "drift"
  ],
  "time": "2026-10-11T22:40:37.097375983Z"
}
```

`/tmp/runc-process…` is written by **runc** while it sets up the `docker exec` — the process is in the container's mount namespace, so `fd.name` starts with `/tmp/`, but it is not yet in the container's cgroup, so `container.id` is the empty string, not `host`. That is why the original `container.id != host` let it through. A later run showed the same file written by `runc:[2:INIT] init` *with* the container id already set, so the rule now excludes both cases (`container.id != ""` and `not proc.name startswith "runc"`). Re-run with the final rule file — exactly one alert, mine:

```
    1 "rule":"Write Below Tmp In Container"
2026-10-11T22:56:04.544309940+0000: Warning File below /tmp opened for writing in container (container=lab9-target container_id=563750fc637c image=alpine user=root uid=0 file=/tmp/my-write.txt cmdline=sh -lc echo test > /tmp/my-write.txt parent=<NA>)
```

It is a nice example of a false positive you only find by running the rule.

SIGHUP reload (done after the alerts were collected) works on 0.39.2:

```
SIGHUP received, restarting...
Events detected: 4
Triggered rules by rule name:
   Read sensitive file untrusted: 1
   Terminal shell in container: 1
   Write Below Tmp In Container: 2
Loading rules from:
   ...
   /etc/falco/rules.d/custom-rules.yaml | schema validation: ok
```

### Incident-relevant field not in the human-readable message

**`hostname`** (`"hostname": "1487a13d88ef"`). The message text says *which container* did what, but not *on which machine Falco saw it*: `hostname` is the node the sensor runs on (here the Falco container's own hostname; in a cluster DaemonSet it is the node name). During an incident that is the first pivot — which node to cordon, whose kernel/containerd logs to pull, and whether the same container id shows up on other nodes. Close seconds: `tags` (`["container","drift"]`, and MITRE IDs like `T1059` on the built-in rules) for routing/triage, and `rule` + `priority` as structured fields that a SIEM can filter on without parsing free text.

### False positives and tuning

The rule fires on every `/tmp` write in every container, and plenty of legitimate software writes there: Node/Python apps buffering uploads (Juice Shop's own file upload goes through a temp file), `pip`/`npm` caches during a build container, Java/JVM `hsperfdata_*` files, nginx `client_body_temp`, and any test runner. A JVM service would raise an alert on every start. I would keep the detection but scope it: add an exception list keyed on `container.image.repository` + `proc.name` for images known to use `/tmp` (e.g. `(image=eclipse-temurin, proc.name=java)`) using Falco's `exceptions:` block rather than editing the condition, and/or lower it to `NOTICE` for known images while keeping `WARNING` for writes of executable content (`/tmp/*.sh`, files later `execve`'d — the stronger "drop and execute" signal that Falco's `Drop and execute new binary in container` rule covers). The hardened manifests make this easier: with `readOnlyRootFilesystem: true` and `/tmp` as the only writable mount, `/tmp` is the *only* place drift can happen, so the alert is worth keeping and tuning rather than deleting. The run itself showed the first exception to add: runc's `/tmp/runc-process*` file written during every `docker exec`, which the rule now filters.

## Task 2 — The same rule, before deployment

Conftest 0.69.0 (OPA 1.19.0). Full output in the appendix.

### 9.4 Shipped policies

| Input | Result |
|---|---|
| `k8s/juice-hardened.yaml` | 30 tests, **30 passed**, 0 warnings, 0 failures |
| `k8s/juice-unhardened.yaml` | 30 tests, 20 passed, **2 warnings, 8 failures** |
| `compose/juice-compose.yml` | 15 tests, **15 passed**, 0 warnings, 0 failures |

Test count = rules × documents across all namespaces: 15 rules (11 in `k8s.security`, 4 in `compose.security`) × 2 YAML documents (Deployment + Service) = 30 for each Kubernetes file; × 1 document = 15 for the Compose file.

Unhardened failures mapped to rules in `k8s-security.rego`:

| Conftest message | Rule |
|---|---|
| `container "juice" uses disallowed :latest tag` | `deny` — `endswith(c.image, ":latest")` |
| `container "juice" must set runAsNonRoot: true` | `deny` — `not c.securityContext.runAsNonRoot` |
| `container "juice" must set allowPrivilegeEscalation: false` | `deny` — `not c.securityContext.allowPrivilegeEscalation == false` |
| `container "juice" must set readOnlyRootFilesystem: true` | `deny` — `not c.securityContext.readOnlyRootFilesystem == true` |
| `container "juice" missing resources.requests.cpu` / `.memory` | `deny` — `not c.resources.requests.cpu` / `.memory` |
| `container "juice" missing resources.limits.cpu` / `.memory` | `deny` — `not c.resources.limits.cpu` / `.memory` |
| `should define readinessProbe` / `livenessProbe` (WARN) | `warn` — `not c.readinessProbe` / `not c.livenessProbe` |

**A gap the counts hide.** The unhardened container has no `securityContext` at all, yet `must drop ALL capabilities` is *not* among its failures. The rule is `not has_value(c.securityContext.capabilities.drop, "ALL")`: when `capabilities.drop` does not exist, the argument is undefined, the call cannot be evaluated, and the rule body fails instead of the `not` succeeding. So the policy catches a container that drops the *wrong* capabilities but never one that drops *none*. I checked this with a two-container fixture:

```
# container "a": no securityContext;  container "b": capabilities.drop: ["NET_RAW"]
$ conftest test t.yaml --policy <shipped> --all-namespaces | grep capab
FAIL - t.yaml - k8s.security - container "b" must drop ALL capabilities
```

Only `b` is flagged. The fix is to default the lookup, e.g. `drops := object.get(c, ["securityContext","capabilities","drop"], [])` before `not has_value(drops, "ALL")`.

### Why Compose and Kubernetes need separate rules; what the Compose pass means

The requirement is the same ("non-root, read-only root, no capabilities"), but the data is shaped differently — Compose has `services.<name>.user`, `read_only`, `cap_drop`, `security_opt` on each service, Kubernetes has `spec.template.spec.containers[].securityContext.runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop` — and a Rego rule matches on input paths, so one rule cannot read both formats. The Compose file passing all 15 means much less than it looks: only **4** of those checks are Compose rules (the other 11 are Kubernetes rules gated on `input.kind == "Deployment"` that never applied), and a pass is only evidence if the rule is known to fail on a bad input. Testing that with a bare Compose service (image + ports, nothing else) shows the same undefined-path gap as above:

```
$ conftest test compose-bad.yml --policy <shipped> --all-namespaces
FAIL - compose-bad.yml - compose.security - services must set an explicit non-root user
FAIL - compose-bad.yml - compose.security - services must set read_only: true

15 tests, 13 passed, 0 warnings, 2 failures, 0 exceptions
```

The `cap_drop: ALL` deny and the `no-new-privileges` warn never fire when the key is missing entirely, so the Compose file passing "drop ALL" proves it complies, but a file without `cap_drop` would have passed too.

### 9.5 Extra policy

`labs/lab9/policies/extra/hardening.rego` — conftest loads the policy directory recursively and `--all-namespaces` evaluates every package, so a new package `k8s.hardening` in a subfolder is picked up next to `k8s.security`.

```rego
package k8s.hardening

# Minimum UID we accept when a container pins runAsUser explicitly.
# UIDs below 10000 overlap system/service accounts on most host images,
# so a container escape lands as a real, possibly privileged, host user.
min_uid := 10000

containers contains c if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
}

# DENY: image must be pinned by digest, not by a mutable tag.
deny contains msg if {
  c := containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image %q must be pinned by digest (@sha256:...)", [c.name, c.image])
}

# WARN: an explicit runAsUser must be a high, non-system UID.
warn contains msg if {
  c := containers[_]
  uid := c.securityContext.runAsUser
  uid < min_uid
  msg := sprintf("container %q runAsUser %d is below %d; use a high UID that does not exist on the host", [c.name, uid, min_uid])
}
```

Why these two: the shipped policy only rejects `:latest`, so `:v19.0.0` passes even though a tag is mutable and can be re-pushed after the image was scanned; a digest pins exactly the bytes that were scanned in Lab 4. `runAsNonRoot` stops UID 0 but allows UID 1, 33 (`www-data`), 1000 (the first real user on most hosts); a high UID means a container escape lands as a user that owns nothing on the node.

Violating manifest `labs/lab9/manifests/k8s/juice-violates-extra.yaml` — a copy of `juice-hardened.yaml` with two changes, so only the new rules can fire:

```yaml
          image: bkimminich/juice-shop:v19.0.0   # tag, not digest -> deny
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000                      # below 10000 -> warn
```

Runs (shipped + extra policies):

```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces

34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/manifests/k8s/juice-violates-extra.yaml --policy labs/lab9/policies --all-namespaces
WARN - labs/lab9/manifests/k8s/juice-violates-extra.yaml - k8s.hardening - container "juice" runAsUser 1000 is below 10000; use a high UID that does not exist on the host
FAIL - labs/lab9/manifests/k8s/juice-violates-extra.yaml - k8s.hardening - container "juice" image "bkimminich/juice-shop:v19.0.0" must be pinned by digest (@sha256:...)

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
```

Side effects: the unhardened manifest now has 9 failures (the digest rule also catches `:latest`), and the Compose file goes to 17/17 passing (the two new rules do not apply to it).

### CI or runtime — if I could only keep one

For digest pinning I would keep the **Conftest rule in CI**: it is a property of the manifest, fully decidable before anything runs, it blocks the deploy instead of reporting it afterwards, and the fix (replace the tag with a digest) is cheap for the developer at PR time. A Falco rule could only see the consequence at runtime (`container.image.digest` not in an allow-list) and alert after the unscanned image is already running. What runtime still buys is coverage of everything that never passed through CI — `kubectl run`/`kubectl edit` by hand, a Helm chart or operator that renders the manifest at deploy time, a mutating webhook that rewrites the image — and for the UID rule, the actual UID the process ran as (`user.uid`), which can differ from the manifest when the image's `USER` is used and `runAsUser` is absent.

## Bonus — Catch a cryptominer

```yaml
- list: miner_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]

- list: miner_binaries
  items: [xmrig, xmr-stak, minerd, cpuminer, cpuminer-multi, ccminer, cgminer, bfgminer, ethminer, t-rex, nbminer, lolminer]

# Raw-socket tools: an application container has no reason to run these,
# and droppers use them to talk to pools/C2 when no miner binary is present yet.
- list: raw_net_tools
  items: [nc, ncat, netcat, socat, telnet]

- rule: Possible Cryptominer Pool Connection
  desc: >
    A process in a container attempted an outbound connection to a port
    commonly used by mining pools (signal 1) AND the process is a known miner
    binary, a raw network tool, or its command line mentions the stratum
    protocol (signal 2). The port is taken from the address the process
    passed to connect() (evt.arg.addr) as well as from the socket tuple
    (fd.sport): on a refused connection the kernel returns no tuple, so
    fd.sport is empty, but the requested address is always there.
  condition: >
    evt.type = connect
    and container.id != host
    and (fd.typechar = 4 or fd.typechar = 6)
    and (fd.sport in (miner_pool_ports)
         or evt.arg.addr endswith ":3333"
         or evt.arg.addr endswith ":4444"
         or evt.arg.addr endswith ":5555"
         or evt.arg.addr endswith ":7777"
         or evt.arg.addr endswith ":14444")
    and (proc.name in (miner_binaries)
         or proc.name in (raw_net_tools)
         or proc.cmdline contains "stratum+tcp"
         or proc.cmdline contains "stratum+ssl")
  output: >
    Possible cryptominer connecting to a pool port
    (container=%container.name container_id=%container.id image=%container.image.repository
    proc=%proc.name pid=%proc.pid cmdline=%proc.cmdline user=%user.name
    requested=%evt.arg.addr dest=%fd.sip:%fd.sport connection=%fd.name result=%evt.res)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control, mitre_impact, T1496]
```

Run (`labs/lab9/falco-bonus.ps1`, Falco 0.39.2, final rule file):

```
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333'                 # nothing listens -> exit=1
$ docker exec -d lab9-target sh -c 'nc -l -p 3333 > /dev/null'            # local listener, still no real pool
$ docker exec lab9-target sh -c 'echo hi | nc -w 2 127.0.0.1 3333'        # accepted -> exit=0
$ docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
    3 "rule":"Possible Cryptominer Pool Connection"
```

Alert for the **refused** connection:

```json
{
  "hostname": "b0477ac83460",
  "output": "2026-10-11T22:56:04.634597429+0000: Critical Possible cryptominer connecting to a pool port (container=lab9-target container_id=563750fc637c image=alpine proc=nc pid=4384 cmdline=nc -w 2 127.0.0.1 3333 user=root requested=127.0.0.1:3333 dest=<NA>:<NA> connection=0.0.0.0:0 result=<NA>)",
  "output_fields": {
    "container.id": "563750fc637c",
    "container.image.repository": "alpine",
    "container.name": "lab9-target",
    "evt.arg.addr": "127.0.0.1:3333",
    "evt.res": null,
    "evt.time.iso8601": 1791759364634597429,
    "fd.name": "0.0.0.0:0",
    "fd.sip": null,
    "fd.sport": null,
    "proc.cmdline": "nc -w 2 127.0.0.1 3333",
    "proc.name": "nc",
    "proc.pid": 4384,
    "user.name": "root"
  },
  "priority": "Critical",
  "rule": "Possible Cryptominer Pool Connection",
  "source": "syscall",
  "tags": [
    "T1496",
    "container",
    "mitre_command_and_control",
    "mitre_impact",
    "network"
  ],
  "time": "2026-10-11T22:56:04.634597429Z"
}
```

The accepted connection fires twice — once on `connect()` entry (`requested=127.0.0.1:3333`) and once on its exit, where the socket tuple is now filled in:

```
2026-10-11T22:56:09.841928575+0000: Critical Possible cryptominer connecting to a pool port (container=lab9-target container_id=563750fc637c image=alpine proc=nc pid=4428 cmdline=nc -w 2 127.0.0.1 3333 user=root requested=<NA> dest=127.0.0.1:3333 connection=127.0.0.1:38271->127.0.0.1:3333 result=SUCCESS)
```

**What I had to change.** My first version matched only `fd.sport in (miner_pool_ports)` and fired only on the accepted connection (`result=SUCCESS`); the refused one produced nothing. A temporary debug rule (`evt.type = connect and proc.name = nc`) showed why, on Falco 0.39.2:

```
dir=> args=fd=3(<4>0.0.0.0:0) addr=127.0.0.1:3333          # connect() entry: requested address is there
dir=< res=ECONNREFUSED  tuple=NULL  fd.sport=<NA>          # exit: no socket tuple, so no fd.sport
```

On a failed `connect()` the kernel never builds a connection, so the exit event carries `tuple=NULL` and every `fd.*` network field is empty. The *requested* address is still in the syscall arguments, so the rule now also matches `evt.arg.addr` (one `endswith ":<port>"` per pool port). Falco 0.43 drops entry events and copies the requested address into the exit event, which is why the lab's hint about `evt.dir=<` works there; the condition above covers both.

**Why a refused connection is enough.** Falco does not watch the network; it hooks the `connect()` system call in the kernel (modern eBPF probe on the syscall tracepoints). The *attempt* — this process, in this container, asked the kernel to connect to `127.0.0.1:3333` — is fully visible in the syscall arguments before the kernel even tries the handshake, and the outcome (`ECONNREFUSED` vs `SUCCESS`) is just the return value. So it does not matter whether a pool answers, a NetworkPolicy drops the packet, or the pool is dead: the intent is recorded. That puts Falco **on the node, at the syscall boundary between the container and the shared kernel** — below the application (which cannot hide the call by lying in its logs) and before the network (so it sees connections that never leave the host). The debug run above is the proof: with nothing listening, the only evidence of the attempt is the `connect()` entry with `addr=127.0.0.1:3333`.

**Evasion.** The port list and the process name are the free parts to evade: the attacker sets `--url pool:443` or renames `xmrig` to `node`, which costs nothing and drops both signals in my rule. What is expensive to change is the behaviour mining requires: sustained high CPU at the container's limit, a long-lived outbound TCP session speaking the Stratum JSON-RPC (`mining.subscribe`, `mining.submit`), and connections to a destination that the workload has never talked to before. To catch the evasion I would add a rule on outbound connections from the Juice Shop container to *any* destination outside an allow-list (it should only receive traffic), match on the miner's arguments rather than its name (`--donate-level`, `-a rx/0`, `stratum+`), alert on `execve` of any binary not present in the image (Falco's drop-and-execute rule), and pair it with CPU-throttling metrics from the resource limits Task 2 already enforces.

## Appendix — raw conftest output

```
### shipped policies: labs/lab9/manifests/k8s/juice-hardened.yaml

30 tests, 30 passed, 0 warnings, 0 failures, 0 exceptions
exit=0
### shipped policies: labs/lab9/manifests/k8s/juice-unhardened.yaml
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag

30 tests, 20 passed, 2 warnings, 8 failures, 0 exceptions
exit=1
### shipped policies: labs/lab9/manifests/compose/juice-compose.yml

15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions
exit=0
### shipped + extra: labs/lab9/manifests/k8s/juice-hardened.yaml

34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions
exit=0
### shipped + extra: labs/lab9/manifests/k8s/juice-violates-extra.yaml
WARN - labs/lab9/manifests/k8s/juice-violates-extra.yaml - k8s.hardening - container "juice" runAsUser 1000 is below 10000; use a high UID that does not exist on the host
FAIL - labs/lab9/manifests/k8s/juice-violates-extra.yaml - k8s.hardening - container "juice" image "bkimminich/juice-shop:v19.0.0" must be pinned by digest (@sha256:...)

17 tests, 15 passed, 1 warning, 1 failure, 0 exceptions
exit=1
### shipped + extra: labs/lab9/manifests/k8s/juice-unhardened.yaml
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define livenessProbe
WARN - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" should define readinessProbe
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.limits.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.cpu
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" missing resources.requests.memory
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set allowPrivilegeEscalation: false
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set readOnlyRootFilesystem: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" must set runAsNonRoot: true
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.security - container "juice" uses disallowed :latest tag
FAIL - labs/lab9/manifests/k8s/juice-unhardened.yaml - k8s.hardening - container "juice" image "bkimminich/juice-shop:latest" must be pinned by digest (@sha256:...)

34 tests, 23 passed, 2 warnings, 9 failures, 0 exceptions
exit=1
### shipped + extra: labs/lab9/manifests/compose/juice-compose.yml

17 tests, 17 passed, 0 warnings, 0 failures, 0 exceptions
exit=0
```
