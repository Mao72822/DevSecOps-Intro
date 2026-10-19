# Lab 12 — VM-Backed Container Isolation with Kata

**Environment:** Windows 11 → WSL2 (Ubuntu), kernel `6.6.87.2-microsoft-standard-WSL2`, `/dev/kvm` present. containerd v2.4.1, nerdctl v2.4.1, runc 1.5.2 (from the `nerdctl-full` bundle). **Kata 4.1.0** static build (`/opt/kata/VERSION` = 4.1.0), pinned — not "latest". Image `alpine:3.20`.

Kata 4.1.0 ships the Rust **runtime-rs** shim (`/opt/kata/runtime-rs/bin/containerd-shim-kata-v2`) with **dragonball** as the VMM (`/etc/kata-containers/configuration.toml → configuration-dragonball.toml`). Two reproducibility notes: the shim had to be symlinked onto `PATH` (the static build drops it under `/opt/kata/runtime-rs/bin`, not `/opt/kata/bin`), and `nerdctl --runtime=io.containerd.kata.v2` resolves the shim by binary name directly, so it works regardless of which CRI plugin block the config edit landed in. The `cannot set cgroup manager to "systemd"` line nerdctl prints for Kata is a non-fatal warning. All raw output is in `labs/lab12/results/`.

## Task 1 — Two runtimes, one image

### Kernel

```
host   kernel: 6.6.87.2-microsoft-standard-WSL2
runc   kernel: 6.6.87.2-microsoft-standard-WSL2
kata   kernel: 6.18.35
```

runc reports the **host** kernel exactly; Kata reports **6.18.35**, its own guest kernel, which does not match the host.

### Devices and capabilities, side by side

| | runc | kata |
|---|---|---|
| `ls /dev \| wc -l` (unprivileged) | 15 | 14 |
| `CapEff` (unprivileged) | `00000000a80425fb` | `00000000a80425fb` |

The capability masks are **identical** — both runtimes apply containerd's default ~14-capability set (`a80425fb`), dropping the same dangerous ones. The device lists are nearly the same size, but they are not the same devices: runc's `/dev` is a filtered view of the host's device tree, Kata's is the guest VM's own `/dev`.

### What the kernel line tells an attacker

Under runc, `uname -r` returns `6.6.87.2-microsoft-standard-WSL2` — the host's kernel, because the container shares it. To an attacker who has just landed in the container, that one line is a targeting aid: it names the exact kernel version, so they know which kernel privilege-escalation CVEs to try, and a working kernel exploit is a **host** compromise, since the same kernel runs everything on the box. Under Kata the answer is `6.18.35`, a separate kernel that belongs to a disposable guest VM. The attacker no longer learns the host kernel from inside, and a kernel exploit now only buys them root on a throwaway guest — to reach the host they must additionally break out of the VM (hypervisor / virtio boundary), a far higher bar. The identical capability masks make the point sharper: the same caps are granted either way; what changed is the kernel those caps operate against.

## Task 2 — What the isolation costs

### Startup (warm-up discarded, 5 timed runs, seconds)

| runtime | runs | median |
|---|---|---|
| runc | 0.46, 0.48, 0.51, 0.56, 0.48 | **0.48** |
| kata | 1.30, 1.37, 1.27, 1.39, 1.37 | **1.37** |

Median, not mean, as required. Both numbers include identical `nerdctl` + containerd overhead, so neither is the runtime measured in isolation — but that overhead cancels in the comparison, so the ~0.9 s **delta** (≈2.9×) is a fair measure of what the VM boot costs. (It is ~3× rather than the ~10× the lab anticipates because dragonball is a lightweight microVM; QEMU-backed Kata is typically closer to an order of magnitude.)

### I/O (512 MiB, `dd … conv=fsync`)

| runtime | throughput |
|---|---|
| runc | 1.3 GB/s |
| kata | 245.7 MB/s |

≈5.3× slower under Kata. The benchmark writes to a **file** (not `/dev/null`) with `fsync` on purpose: `/dev/null` discards in the kernel and measures nothing about storage, whereas forcing 512 MiB through the container filesystem to stable storage exercises exactly the layer where a VM-backed runtime differs — Kata's write crosses virtio-fs/virtio-blk into the guest and back, while runc writes more or less straight to the host's overlayfs.

### Memory overhead per container

| runtime | MemAvailable drop | VMM/shim RSS |
|---|---|---|
| runc | within noise (≈0, a few MiB) | — |
| kata | 169 MiB | 173 MiB |

**Method:** start one idle `sleep` container, read the drop in `/proc/meminfo` `MemAvailable` immediately after, and cross-check against the resident set (RSS) of the Kata VMM/shim process. The two methods agree: ≈**170 MiB per Kata container** — the guest kernel plus the VMM — against essentially nothing for runc (just the process and its namespaces). This is dragonball at its default guest RAM; QEMU would be higher.

### Workload verdicts

| Workload | Verdict | Why |
|---|---|---|
| Multi-tenant CI running untrusted PRs / arbitrary customer code | **Kata** | Hostile code next to other tenants is exactly the VM boundary's job; a container escape only reaches a disposable guest kernel, not the host or its neighbours. The startup/I-O/memory tax is worth it. |
| Internal high-throughput batch ETL on first-party data, disk-bound | **runc** | Trusted code, and the ~5× I/O penalty plus ~170 MiB/container would dominate. The isolation buys little against your own code. |
| High-frequency short-lived FaaS running third-party functions | **Needs more information** | Depends on trust boundary and invocation rate. Untrusted + moderate rate → Kata (even ~1.4 s is fine, amortised, and isolation matters). Extremely high invocation rate → the per-invocation startup and ~170 MiB may rule it out, or force a pre-warmed pool. Trust level and frequency decide it. |

### For which workloads does the startup gap not matter

A ~0.9 s one-time startup difference is irrelevant to any **long-running service** — a web server, database, message broker, or daemon that is created once and then runs for days or weeks. The container is started essentially never relative to its lifetime, so the boot cost is amortised to zero and only steady-state CPU/I-O/memory matter. The gap only bites workloads that create containers constantly: per-request or per-job short-lived containers, dense autoscaling, and CI fan-out, where you pay the boot cost on every unit of work.

## Bonus — An escape that Kata stops

### Both runs, and the host file

Payload (identical but for the runtime flag): a `--privileged` container with `-v /tmp:/host_tmp` writing through the mount.

```
== runc ==
  container said: wrote from inside 6.6.87.2-microsoft-standard-WSL2
  host /tmp/lab12-target BEFORE: original
  host /tmp/lab12-target AFTER : OVERWRITTEN      => HOST FILE MODIFIED (escape succeeded)

== kata ==
  container said: level=fatal failed to create shim task ...
      Caused by: 0: get host path failed  1: No such file or directory (os error 2)
      (hypervisor::device::util::get_host_path)
  host /tmp/lab12-target BEFORE: original
  host /tmp/lab12-target AFTER : original          => host file intact (contained)
```

On runc the privileged container runs and the write lands on the host file. On Kata the container **never starts**: the runtime-rs device handler tries to map the host's devices into the guest (that is what `--privileged` asks for) and aborts because a host device path cannot be resolved. The host file is untouched because the workload did not run.

### Device count and capability mask, privileged

| runtime | privileged `/dev` count | privileged `CapEff` |
|---|---|---|
| runc | **185** | `000001ffffffffff` (all capabilities) |
| kata | n/a — privileged container refuses to start on this host | n/a |

For reference, unprivileged was 15 devices / `a80425fb`. On runc, `--privileged` jumps `/dev` from 15 to **185** (the host's device tree, including host disks) and the mask to the full set `1ffffffffff`. On Kata the privileged container cannot be created at all here, so there is no mask to read — the misconfiguration that "works" on runc does not even launch.

### What `--privileged` actually grants, and to what

`--privileged` gives all capabilities, the host's device nodes, and relaxed seccomp/AppArmor **over whatever kernel the container shares**. On runc that kernel is the host's, so the flag is a near-complete handover of the host: even without the bind mount, the container could mount a host disk out of `/dev` and read or write anything. On Kata the same privileges would apply to the **guest** kernel and the guest's virtual devices — the host disk is not in the guest's `/dev` — so the blast radius is a disposable VM. The honest nuance: it did not "partly work," it failed to start. And note the bind mount itself is **not** what Kata would have blocked — a rw `-v /tmp:/host_tmp` is deliberately shared into the guest over virtio-fs, so had the container started, a write to that one explicitly-shared path could still reach the host. What Kata removes is the *implicit* host access (host devices, the host kernel, every other host file), not a directory you chose to hand in.

### The honest limit

Kata does not protect what you explicitly give away: a read-write bind mount (or any shared `virtio-fs` path) is passed straight into the guest, so Kata is no defence against a container writing to a host directory you deliberately mounted — nor against a guest-kernel or hypervisor 0-day, or side-channels.
