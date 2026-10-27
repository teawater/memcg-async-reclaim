# memcg-async-reclaim

BPF-driven memory cgroup reclaim tooling. In its `bench` and `watch` modes a
BPF program watches the workingset refaults (file and anon) of a *monitor*
cgroup and, when they grow past a threshold, reclaims memory from a *target*
cgroup in bounded batches from `bpf_wq` work callbacks, through the
`bpf_proactive_reclaim()` kfunc; the monitored workload never blocks on the
reclaim. Its `lowmin` mode instead uses the `bpf_memcg_ops` `memory.low` /
`memory.min` policy hooks to keep a chosen cgroup's cache hot while the kernel
reclaims a pressured sibling. `watch` can use those same hooks on its monitor
cgroup too, either alongside reclaim or instead of it.

`bench`/`watch` are the out-of-tree version of a sample submitted to the
kernel's `samples/bpf` directory as ["samples/bpf: Add memcg async reclaim
example"](https://sashiko.dev/#/message/de7adb6bafa3b808e29c0630f7ed9a2003e5e447.1790222105.git.zhuhui%40kylinos.cn);
`lowmin` is added here to exercise the memcg_ext protection hooks.

## Modes

**bench** - creates a high/low priority cgroup pair, runs a memory-pressured
page-cache workload in both and reports the effect of the asynchronous
reclaim on the pressured one. By default the same workload first runs
without the BPF program to produce a baseline. Self-contained: creates and
removes its own cgroups and workload files.

**lowmin** - like bench, but protects a cgroup with the `memory.low` /
`memory.min` BPF policy hooks (`bpf_memcg_ops`' `low_policy`/`min_policy`)
instead of refault-driven reclaim. It creates a parent with `memory.max` and
two children, `prot` and `victim`, runs the page-cache workload in both, and
attaches the policy to `prot`. The parent's limit forces kernel reclaim, which
walks both children; the hook asserts that `prot` is below its threshold, so
the kernel skips it and takes the memory from `victim` instead - `prot` keeps
its cache and finishes faster. `--level` picks `low` (soft), `min` (hard) or
`both`. Two things to know: the hook only fires for the reclaim *target's
descendants*, never the target itself, so the protected cgroup has to be a
child of the reclaimed parent; and `prot` carries no real `memory.low`/`min`,
so the protection is purely the BPF policy's (a real threshold would make the
kernel decide before ever asking BPF). Only `low_policy`/`min_policy` are
used - this mode does not touch `high_policy`.

**watch** - watches an existing cgroup and keeps reclaiming from another one
for as long as the program runs, so it can serve as a simple proactive-reclaim
daemon. Removing the target while it runs is handled: reclaim stops and the
events say so. `--observe` picks how the monitor is watched and `--control`
what to do about it - reclaim the target, protect the monitor with the
`memory.low`/`memory.min` BPF hooks, or both; the defaults are the original
behaviour. See [watch methods](#watch-methods).

## Requirements

Kernel:

- the `bpf_proactive_reclaim()` kfunc, restricted to `BPF_PROG_TYPE_SYSCALL`
  (not yet in mainline; build a kernel with the patch series applied)
- for `lowmin`, and for `watch --control low|min`, the `bpf_memcg_ops`
  struct_ops with `low_policy`/`min_policy` (the memcg_ext protection hooks;
  shipped by the same patched kernel)
- `CONFIG_MEMCG`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`
  (`/sys/kernel/btf/vmlinux`), cgroup v2
- swap only for swappiness `201` (anon-only) or anon-heavy watch workloads

Build:

- clang (BPF target), bpftool, libbpf development headers and library,
  gcc, make
- if the distro libbpf is too old for `bpf_wq` skeletons or for `lowmin`'s
  struct_ops cgroup attach, point `LIBBPF_CFLAGS`/`LIBBPF_LIBS` at a source
  build, e.g. the kernel's `tools/lib/bpf`

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

Linking is dynamic by default. If the binary is built against a newer libbpf
than the runtime finds - it then fails with e.g. ``version `LIBBPF_1.8.0' not
found`` - add `STATIC=1` to link libbpf/libelf/libz into the binary instead.
Their static archives must be reachable, so keep the `-L` above. `STATIC=1`
also appends `-lzstd`, because the distro `libelf.a` is built with zstd support
but does not pull it in transitively the way `libelf.so` does - so install
`libzstd-dev` too:

```
make STATIC=1 LIBBPF_CFLAGS="-I$KDIR/tools/lib/bpf" \
     LIBBPF_LIBS="-L$KDIR/tools/lib/bpf -lbpf -lelf -lz"
```

## Usage (needs root)

```
sudo ./memcg_async_reclaim bench
sudo ./memcg_async_reclaim lowmin                 # min protection, with baseline
sudo ./memcg_async_reclaim lowmin --level low --events
sudo ./memcg_async_reclaim watch -m /sys/fs/cgroup/high -T /sys/fs/cgroup/low -s 10
sudo ./memcg_async_reclaim watch -m /sys/fs/cgroup/high -T /sys/fs/cgroup/low \
                                  --control reclaim,low  # reclaim low, protect high
sudo ./memcg_async_reclaim watch -m /sys/fs/cgroup/high --control min  # protect only
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

`-i`, `-t`, `-b`, `-n` and `-S` configure the reclaim engine, so in watch mode
they only apply when `--control` includes `reclaim`.

bench options:

| Option | Meaning | Default |
|---|---|---|
| `-l, --limit BYTES` | memory.max for the test cgroups | 32M |
| `-f, --file-size BYTES` | workload file size | 32M |
| `-R, --read-times N` | workload re-read iterations | 50 |
| `--no-baseline` | skip the run without the BPF program | |

lowmin options (shares `-l`, `-f`, `-R`, `--no-baseline` with bench):

| Option | Meaning | Default |
|---|---|---|
| `-L, --level LEVEL` | `low`, `min` or `both`: which policy asserts BELOW | min |
| `--events` | also read `prot`'s `memory.events` low count | off |

Sizing is chosen per level so the demo is clean and OOM-free. With `--level
min` (the default), `prot` is hard-protected and immune to reclaim, so its fill
must stay below the parent limit or `victim` is left nothing reclaimable and
the memcg OOMs: `-f` defaults to 3/4 of `-l`. With `--level low` the protection
is soft and cannot OOM, so `-f` defaults to a gentler 5/8 of `-l` - low enough
that `victim` alone absorbs the reclaim and `prot` is never breached (its
`memory.events` low count stays 0). An explicit `-f >= -l` is shrunk to 3/4 of
the limit with a note. For any visible effect the two children together must
still exceed the limit (`2 * -f > -l`).

watch options:

| Option | Meaning | Default |
|---|---|---|
| `-m, --monitor PATH` | cgroup to watch | required |
| `-T, --target PATH` | cgroup to reclaim from | required by `--control reclaim` |
| `-D, --duration SEC` | stop after SEC seconds instead of on signal | |
| `-s, --stats SEC` | print a statistics line every SEC seconds | 10 |
| `--observe METHODS` | how the monitor is watched | `refault` |
| `--control METHODS` | what to do about it | `reclaim` |

`BYTES` accepts a K, M or G suffix.

One `bpf_proactive_reclaim()` call reclaims at most the kernel's
`MEMCG_CHARGE_BATCH` pages, so `--batch` above that limit only means a
round needs more callbacks, not that a single callback does more.

### watch methods

Both selectors take a comma-separated list, and repeating the option
accumulates, so `--control reclaim,low` and `--control reclaim --control low`
are the same. `low` and `min` name the same `bpf_memcg_ops` hook on both sides:
observing it means treating the kernel consulting the hook as the pressure
signal, controlling it means answering `BELOW`.

| `--observe` | Meaning |
|---|---|
| `refault` | a timer polls the monitor's workingset refaults; a delta of at least `-t` opens a reclaim round |
| `low`, `min` | the monitor's `low_policy`/`min_policy` hook being consulted is itself the signal - *not implemented yet, the option is rejected* |

| `--control` | Meaning |
|---|---|
| `reclaim` | `bpf_proactive_reclaim()` the target in bounded batches when an observation opens a round |
| `low` | the monitor's `low_policy` answers `BELOW`, so reclaim skips it. Soft: the kernel retries with `memcg_low_reclaim` and reclaims the monitor anyway once nothing else can give, counting a `memory.events` `low` |
| `min` | the monitor's `min_policy` answers `BELOW`. Hard: the monitor is skipped outright, and if nothing else in the hierarchy is reclaimable the memcg OOMs |

With `--control low|min` the periodic statistics line gains `below=N(+M)`, the
number of times a hook answered `BELOW`. Five things to know:

- The hook is only consulted while the kernel reclaims one of the monitor's
  *ancestors*; reclaiming the monitor itself never asks. So the protection does
  something only when the monitor sits under a pressured parent - typically a
  sibling of the target below a common `memory.max`. Otherwise `below` stays 0.
- A real `memory.low`/`memory.min` on the monitor that already covers its usage
  makes the kernel decide before it ever asks BPF, so the hook never runs.
  Leave both unset.
- The kernel checks `min` before `low` and a `BELOW` from `min` skips the
  cgroup outright, so with `--control low,min` the `low` half never runs.
- The link is on the monitor's cgroup but cgroup struct_ops inherit downward,
  so the hook also runs for the monitor's descendants; the program filters on
  the monitor's id, so only the cgroup named by `-m` is protected, not its
  children. Point `-m` at the cgroup that actually holds the memory.
- `min` has no usage ceiling: a monitor that keeps growing can starve the
  target into a memcg OOM. Use `low` when that matters.

## Results

From the upstream submission cover letter (QEMU VM, 8 GiB RAM, 10 vCPUs,
10 runs, bench mode): the pressured high-priority workload finished in a
median of 2.0s with the asynchronous reclaim versus 15.3s baseline, a
62%-94% speedup per run.

## Layout

| File | Role |
|---|---|
| `memcg_async_reclaim.bpf.c` | BPF side: timer/wq chain, refault trigger, reclaim rounds, low/min protection policy |
| `memcg_async_reclaim_user.c` | CLI, bench harness, lowmin protection demo, watch daemon |
| `memcg_async_reclaim.h` | shared config, ringbuf event structs, watch method masks |
| `cgroup_helpers.[ch]` | vendored from the kernel's selftests |
| `compat.h` | `READ_ONCE`/`WRITE_ONCE`/`__maybe_unused`/`ARRAY_SIZE` fallbacks |

## License

GPL-2.0, see [LICENSE](LICENSE).
