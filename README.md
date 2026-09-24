# memcg-async-reclaim

BPF-driven asynchronous proactive memory cgroup reclaim: a BPF program
watches the workingset refaults (file and anon) of a *monitor* cgroup and,
when they grow past a threshold, reclaims memory from a *target* cgroup in
bounded batches from `bpf_wq` work callbacks, through the
`bpf_proactive_reclaim()` kfunc. The monitored workload never blocks on the
reclaim.

This is the out-of-tree version of a sample submitted to the kernel's
`samples/bpf` directory as ["samples/bpf: Add memcg async reclaim
example"](https://sashiko.dev/#/message/de7adb6bafa3b808e29c0630f7ed9a2003e5e447.1790222105.git.zhuhui%40kylinos.cn).

## Modes

**bench** - creates a high/low priority cgroup pair, runs a memory-pressured
page-cache workload in both and reports the effect of the asynchronous
reclaim on the pressured one. By default the same workload first runs
without the BPF program to produce a baseline. Self-contained: creates and
removes its own cgroups and workload files.

**watch** - watches two existing cgroups and keeps reclaiming for as long as
the program runs, so it can serve as a simple proactive-reclaim daemon.
Removing the target while it runs is handled: reclaim stops and the events
say so.

## Requirements

Kernel:

- the `bpf_proactive_reclaim()` kfunc, restricted to `BPF_PROG_TYPE_SYSCALL`
  (not yet in mainline; build a kernel with the patch series applied)
- `CONFIG_MEMCG`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`
  (`/sys/kernel/btf/vmlinux`), cgroup v2
- swap only for swappiness `201` (anon-only) or anon-heavy watch workloads

Build:

- clang (BPF target), bpftool, libbpf development headers and library,
  gcc, make
- if the distro libbpf is too old for `bpf_wq` skeletons, point
  `LIBBPF_CFLAGS`/`LIBBPF_LIBS` at a source build, e.g. the kernel's
  `tools/lib/bpf`

## Build

```
make
```

`vmlinux.h` is generated from BTF at build time, by default from the
running kernel's `/sys/kernel/btf/vmlinux`. To build for a different
kernel, point `VMLINUX_BTF` at its BTF source, e.g. the `vmlinux` ELF of
a kernel build tree, before running make:

```
export VMLINUX_BTF=/path/to/kernel/linux/vmlinux
make
```

The generated skeleton and CO-RE relocations match that kernel, so the
resulting binary is meant to run on it, not necessarily on the build
host. To use a source-built libbpf:

```
make LIBBPF_CFLAGS="-I$KDIR/tools/lib/bpf" \
     LIBBPF_LIBS="-L$KDIR/tools/lib/bpf -lbpf -lelf -lz"
```

## Usage (needs root)

```
sudo ./memcg_async_reclaim bench
sudo ./memcg_async_reclaim watch -m /sys/fs/cgroup/high -T /sys/fs/cgroup/low -s 10
```

Common options:

| Option | Meaning | Default |
|---|---|---|
| `-i, --interval MS` | monitor tick | bench 2, watch 20 |
| `-t, --threshold N` | refault delta per tick that starts a round | 1 |
| `-b, --batch BYTES` | bytes requested per callback | 128K |
| `-n, --max-batches N` | callbacks per reclaim round | 32 |
| `-S, --swappiness N` | `-1` = the memcg's own, `0..200`, `201` = anon only (needs swap) | -1 |
| `-v, --verbose` | print every reclaim event | off |

bench options:

| Option | Meaning | Default |
|---|---|---|
| `-l, --limit BYTES` | memory.max for the test cgroups | 32M |
| `-f, --file-size BYTES` | workload file size | 32M |
| `-R, --read-times N` | workload re-read iterations | 50 |
| `--no-baseline` | skip the run without the BPF program | |

watch options:

| Option | Meaning | Default |
|---|---|---|
| `-m, --monitor PATH` | cgroup to watch | required |
| `-T, --target PATH` | cgroup to reclaim from | required |
| `-D, --duration SEC` | stop after SEC seconds instead of on signal | |
| `-s, --stats SEC` | print a statistics line every SEC seconds | 10 |

`BYTES` accepts a K, M or G suffix.

One `bpf_proactive_reclaim()` call reclaims at most the kernel's
`MEMCG_CHARGE_BATCH` pages, so `--batch` above that limit only means a
round needs more callbacks, not that a single callback does more.

## Results

From the upstream submission cover letter (QEMU VM, 8 GiB RAM, 10 vCPUs,
10 runs, bench mode): the pressured high-priority workload finished in a
median of 2.0s with the asynchronous reclaim versus 15.3s baseline, a
62%-94% speedup per run.

## Layout

| File | Role |
|---|---|
| `memcg_async_reclaim.bpf.c` | BPF side: timer/wq chain, refault trigger, reclaim rounds |
| `memcg_async_reclaim_user.c` | CLI, bench harness, watch daemon |
| `memcg_async_reclaim.h` | shared config and ringbuf event structs |
| `cgroup_helpers.[ch]` | vendored from the kernel's selftests |
| `compat.h` | `READ_ONCE`/`WRITE_ONCE`/`__maybe_unused` fallbacks |

## License

GPL-2.0, see [LICENSE](LICENSE).
