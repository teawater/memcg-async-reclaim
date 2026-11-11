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

**cmp** - runs one arm of the three-arm `memory.low` request comparison for
the memcg_ext v2 series: a userspace agent writing `memory.low` (`user`), a
`bpf_wq` poller feeding a `low_request` hook (`bpf-poll`), or the decision
taken inside the hook at the collection point (`bpf-hook`). Builds a fresh
topology per run, measures the burst window, and appends one CSV row. See
[the cmp section](#cmp-three-arm-comparison) below.

## Requirements

Kernel:

- the `bpf_proactive_reclaim()` kfunc, restricted to `BPF_PROG_TYPE_SYSCALL`
  (not yet in mainline; build a kernel with the patch series applied)
- for **cmp** only: the memcg_ext v2 series - `bpf_memcg_ops` struct_ops
  with the `low_request` member and the `low_req` arbitration in
  `page_counter` - plus `CONFIG_PSI` **and the `psi=1` boot parameter**
  for the PSI columns and `--trigger poll` (on
  `CONFIG_PSI_DEFAULT_DISABLED=y` kernels PSI is compiled in but off;
  `cmp-run.sh` and the tool now refuse/flag such a dataset instead of
  logging silent zeros)
- `CONFIG_MEMCG`, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`
  (`/sys/kernel/btf/vmlinux`), cgroup v2
- swap only for swappiness `201` (anon-only) or anon-heavy watch workloads

Build:

- clang (BPF target), bpftool, libbpf development headers and library,
  gcc, make
- cmp needs `bpf_map__attach_cgroup_opts`, which the memcg_ext series
  adds to the kernel tree's `tools/lib/bpf` - no distro libbpf has it,
  so build with `KDIR=` pointing at that tree (see [Build](#build))

## Build

```
make KDIR=/path/to/kernel/linux
```

`KDIR` is the one-stop way to build against a specific kernel tree, and
what cmp needs: `vmlinux.h` is generated from that tree's `vmlinux`,
and the libbpf headers and library plus bpftool (if built) are taken
from its `tools/` directory instead of the system installs - including
the `bpf_map__attach_cgroup_opts` that only the memcg_ext series'
`tools/lib/bpf` provides. The tree's `tools/lib/bpf` must be built
beforehand; the link records an rpath to it, so the binary uses it at
run time too.

Without `KDIR`, `vmlinux.h` is generated from the running kernel's
`/sys/kernel/btf/vmlinux` and the system libbpf/bpftool are used -
enough for bench and watch on a kernel that has the reclaim kfunc.
Individual pieces can be overridden in either mode: `VMLINUX_BTF` (any
BTF source, e.g. the `vmlinux` ELF of another build tree), `BPFTOOL`,
and `LIBBPF_CFLAGS`/`LIBBPF_LIBS` for a source-built libbpf.

A fully static binary can be built with `STATIC=1` (e.g.
`make STATIC=1 KDIR=/path/to/kernel/linux`). It runs on hosts without the
matching shared libraries, such as a test VM, and does not depend on the
rpath to the kernel tree's libbpf. Static linking needs libbpf.a (with
KDIR the kernel tree's), plus static versions of the system libraries:
libelf.a, libz.a, libc.a and libzstd.a (package libzstd-dev) - distro
libelf.a is built with zstd compression support, which dynamic linking
resolves automatically but static linking needs `-lzstd` for.

The generated skeleton and CO-RE relocations match the selected
kernel, so the resulting binary is meant to run on it, not necessarily
on the build host. `vmlinux.h` is only generated when missing: after
switching to a different kernel, run `make clean` first so it is
regenerated.

## Usage (needs root)

One binary with three subcommands, plus a protocol runner for cmp.
`bench` and `watch` need a kernel with the `bpf_proactive_reclaim()`
kfunc; `cmp` additionally needs the memcg_ext v2 series and `psi=1` on
the kernel cmdline (see [Requirements](#requirements)).

Common options:

| Option | Meaning | Default |
|---|---|---|
| `-i, --interval MS` | monitor tick | bench 2, watch 20 |
| `-t, --threshold N` | refault delta per tick that starts a round | 1 |
| `-b, --batch BYTES` | bytes requested per callback | 128K |
| `-n, --max-batches N` | callbacks per reclaim round | 32 |
| `-S, --swappiness N` | `-1` = the memcg's own, `0..200`, `201` = anon only (needs swap) | -1 |
| `-v, --verbose` | print every reclaim event | off |

`BYTES` accepts a K, M or G suffix.

One `bpf_proactive_reclaim()` call reclaims at most the kernel's
`MEMCG_CHARGE_BATCH` pages, so `--batch` above that limit only means a
round needs more callbacks, not that a single callback does more.

### bench: self-contained smoke test and demo

Creates its own high/low priority cgroup pair under a private cgroup2
mount and runs the same memory-pressured page-cache workload in both,
twice: first without the BPF program (the baseline), then with it
reclaiming from the low priority side whenever the high priority side
refaults. It reports each side's wall time and the speedup, e.g.
`high: baseline=15.344s reclaim=2.016s speedup=+86.9%`.

```
sudo ./memcg_async_reclaim bench
sudo ./memcg_async_reclaim bench --limit 64M --file-size 64M --read-times 100
sudo ./memcg_async_reclaim bench --no-baseline    # skip the "without BPF" pass
```

bench options:

| Option | Meaning | Default |
|---|---|---|
| `-l, --limit BYTES` | memory.max for the test cgroups | 32M |
| `-f, --file-size BYTES` | workload file size | 32M |
| `-R, --read-times N` | workload re-read iterations | 50 |
| `--no-baseline` | skip the run without the BPF program | |

Everything is self-cleaning: the cgroups and the workload files are
removed on exit. The workload files must live on a *regular* filesystem -
tmpfs pages are not reclaimable without swap - so a setup with only tmpfs
/tmp and working directory is refused at startup. This is the quickest
way to check that the kernel side works at all.

### watch: proactive-reclaim daemon on existing cgroups

Watches one cgroup's workingset refaults with a BPF timer and keeps
reclaiming from another for as long as the program runs, so it serves as
a simple proactive-reclaim daemon. The monitored workload never blocks
on the reclaim: rounds execute from `bpf_wq` work callbacks.

```
sudo ./memcg_async_reclaim watch -m /sys/fs/cgroup/high -T /sys/fs/cgroup/low -s 10
sudo ./memcg_async_reclaim watch -m ... -T ... -D 60 -v    # 60s, log every event
```

Every `--interval` ms the timer compares the monitor's
`workingset_refault_file` + `workingset_refault_anon` sum against the
previous tick; if it grew by at least `--threshold` pages, one reclaim
round starts: up to `--max-batches` work callbacks, each requesting up
to `--batch` bytes from the target with swappiness `--swappiness`. A
`[NNNNs]` statistics line is printed every `--stats` seconds; SIGINT (or
`-D`) stops the daemon.

watch options:

| Option | Meaning | Default |
|---|---|---|
| `-m, --monitor PATH` | cgroup to watch | required |
| `-T, --target PATH` | cgroup to reclaim from | required |
| `-D, --duration SEC` | stop after SEC seconds instead of on signal | |
| `-s, --stats SEC` | print a statistics line every SEC seconds | 10 |

Both paths must exist and have the memory controller enabled (a
`memory.current` file). Removing the target while the daemon runs is
handled: reclaim stops and the statistics say so.

### cmp: one arm of the three-arm comparison

One invocation builds a fresh topology ([below](#topology)), runs one
arm for one measured window, prints a report and appends one CSV row:

```
sudo ./memcg_async_reclaim cmp --impl bpf-hook --burst 64M --csv results.csv
```

`--impl` picks the arm - `user`, `bpf-poll`, `bpf-hook` - or the
`sanity` gate, which requests protection unconditionally and checks
that A keeps its pages. See [the cmp section](#cmp-three-arm-comparison)
for what the arms claim and how to read the report. Single runs are for
smoke tests and calibration; publication data comes from `cmp-run.sh`
below.

cmp options:

| Option | Meaning | Default |
|---|---|---|
| `--impl IMPL` | `user`, `bpf-poll`, `bpf-hook` or `sanity` | required |
| `--trigger T` | U arm wakeup: `timer` or `poll` (PSI) | timer |
| `-i, --interval MS` | U timer tick / B1 poll tick | 5 |
| `--psi-us N` | poll trigger: stall us per 1s window | 10000 |
| `-t, --threshold N` | A `memory.current` fall in pages per second that protects (all arms; rate-normalized, so sample frequency does not matter) | 12800 |
| `--hysteresis MS` | hold protection this long after the evidence stops | 50 |
| `--read-cycle MS` | A's re-read pacing; 0 reads back-to-back | 500 |
| `--filler-sleep MS` | B's rewrite cadence; 0 rewrites back-to-back | 500 |
| `--budget BYTES` | T `memory.low` (shield against global reclaim) | 64M |
| `--tmax BYTES` | T `memory.max`, the pressure source | 160M |
| `--filler BYTES` | B's file cache, the reclaim fodder; A+B must stay under `--tmax` so the ramp is reclaim-free | 112M |
| `--burst BYTES` | C's anon burst; `0` runs without a burst | 0 |
| `--ramp SEC` | settle time before the measured window | 5 |
| `-f, --file-size BYTES` | A's working-set file | 32M |
| `--agent-min BYTES` | agent cgroup `memory.min` (disclosed below) | 8M |
| `-D, --duration SEC` | length of the measured window | 30 |
| `--csv FILE` | append one result row per run | |

`kernel.bpf_stats_enabled` is toggled by the tool per run, so the hook
timing columns are filled without manual setup.

### cmp-run.sh: the full interleaved protocol

The runner turns the tool into a dataset. One invocation executes: a
per-round `sanity` gate (aborts the whole run on failure), the three
arms in **rotating order** so no arm systematically runs on a
colder/warmer machine, `sync + drop_caches` between runs, `ROUNDS`
rounds, and then a phase-2 sweep of the U arm's trigger/interval
frontier (1/5/20/100ms timer + PSI poll), each point repeated
`UCURVE_ROUNDS` times so per-point medians can be reported.

```
sudo ./cmp-run.sh                        # full protocol (~45-50 min on the 8 GiB test VM)
sudo ROUNDS=2 ./cmp-run.sh               # dry run: 2 rounds + the curve phase
sudo ROUNDS=2 U_CURVE=0 ./cmp-run.sh     # pipeline check without phase 2 (~10 min)
```

All output of one invocation lands in a single timestamped run
directory - the unit to copy between machines:

```
run-20261111-071332/
├── results.csv               one row per measured run (phase 1 + phase 2)
└── logs/
    ├── environment.txt       kernel release, swap state, meminfo snapshot
    ├── roundNN-<tag>.log     full stdout of every run, including the sanity gates
    └── void-rounds.txt       runs where protection never engaged (annotated)
```

Every knob is an environment variable. The defaults are the calibrated
production values, and all of them apply to every arm identically - only
`--impl`/`--trigger`/`--interval` may differ between arms, which is the
point of the comparison:

| Variable | Meaning | Default |
|---|---|---|
| `ROUNDS` | phase-1 rounds (each: sanity gate + 3 arms) | 15 |
| `DURATION` / `RAMP` | measured window / settle time, seconds | 30 / 5 |
| `U_CURVE` | 1 = run the phase-2 frontier sweep | 1 |
| `UCURVE_ROUNDS` | repetitions per curve point (median) | 5 |
| `U_TRIGGER` | U arm wakeup in phase 1: `timer` or `poll` | timer |
| `INTERVAL` | U timer tick / B1 poll tick, ms | 5 |
| `PSI_US` | poll trigger: stall us per 1s window | 10000 |
| `THRESHOLD` | A `memory.current` fall that protects, pages/s | 12800 |
| `HYSTERESIS` | hold protection this long after the evidence stops, ms | 50 |
| `READ_CYCLE_MS` / `FILLER_SLEEP_MS` | A re-read / B rewrite pacing, ms | 500 / 500 |
| `BUDGET` / `TMAX` | T's `memory.low` shield / `memory.max` pressure | 64M / 160M |
| `FILLER` / `BURST` / `AFILE` / `AGENT_MIN` | B fodder / C anon burst / A file / agent `memory.min` | 112M / 64M / 32M / 8M |
| `RUNDIR` / `CSV` / `LOGDIR` | output locations | `run-<ts>` and paths inside it |
| `TOOL` | path to the binary | `./memcg_async_reclaim` |

Workflow on a fresh machine:

1. **Build** against the kernel under test and copy the binary plus
   `cmp-run.sh` over; `make STATIC=1 KDIR=/path/to/kernel/linux` for a
   VM without the matching libraries (see [Build](#build)).
2. **Boot the VM with `psi=1`** on the kernel cmdline. Both the script
   and the tool refuse (or loudly flag) a kernel without
   `/proc/pressure/memory`: every PSI column would silently read 0 and
   the poll rows would die inside the agent.
3. **Calibrate (plan P0)** before the first counted round - short
   windows, one run per arm; all three must engage protection promptly
   (`valid=1`, small `first_protect_ms`) and an unprotected A must
   visibly lose pages:

   ```
   sudo ./memcg_async_reclaim cmp --impl sanity --duration 10 --ramp 3 \
        --burst 64M --read-cycle 5000 --hysteresis 30000
   sudo ./memcg_async_reclaim cmp --impl user     --duration 10 --ramp 3 \
        --burst 64M --read-cycle 5000 --hysteresis 30000 --csv p0.csv
   sudo ./memcg_async_reclaim cmp --impl bpf-poll --duration 10 --ramp 3 \
        --burst 64M --read-cycle 5000 --hysteresis 30000 --csv p0.csv
   sudo ./memcg_async_reclaim cmp --impl bpf-hook --duration 10 --ramp 3 \
        --burst 64M --read-cycle 5000 --hysteresis 30000 --csv p0.csv
   ```

   Adjust `THRESHOLD` / `READ_CYCLE_MS` / `FILLER_SLEEP_MS` / `PSI_US`
   until they do, and publish the calibrated values with the results.
4. **Dry run**: `sudo ROUNDS=2 ./cmp-run.sh` exercises the whole
   pipeline - gates, rotation, logs, CSV, void annotation - before
   spending an hour on the formal run.
5. **Formal run**: `sudo ./cmp-run.sh`; copy the run directory back and
   report medians with IQR per arm and per curve point, publishing the
   raw rows (see [Metrics](#metrics-per-run-one-csv-row)).

Troubleshooting:

| Symptom | Cause and fix |
|---|---|
| script: `ERROR: PSI is disabled`; tool: `memory.pressure unavailable` | kernel booted without `psi=1`; add it to the cmdline |
| `agent child failed at: open memory.pressure` (exit 6) / `arm PSI trigger` (exit 7) | same; child exit codes 1-7 mean join cgroup, write file, read file, time file, open files, open PSI, arm PSI trigger |
| `sanity gate FAILED ... aborting` | the protection chain did not demonstrably work: check the kernel has the v2 series; T must stay a direct child of the cgroup2 root and A+B must stay under `--tmax` |
| `ROUND VOID` warnings | protection never engaged in that run; on the 100ms/poll curve points this *is* the data point, elsewhere it means calibration drift |
| `hook run_time unavailable` | `kernel.bpf_stats_enabled` could not be toggled; the overhead columns of that row stay empty |

## Results

From the upstream submission cover letter (QEMU VM, 8 GiB RAM, 10 vCPUs,
10 runs, bench mode): the pressured high-priority workload finished in a
median of 2.0s with the asynchronous reclaim versus 15.3s baseline, a
62%-94% speedup per run.

## cmp: three-arm comparison

Answers, with numbers, the question asked three times on the memcg_ext
threads - most recently by Tejun Heo and before that by Michal Hocko: *why
can the same not be achieved by changing `memory.low` from userspace?*

The claim under test is a **window**, not a throughput: direct reclaim
examines memcgs one at a time, and a userspace agent cannot act for the
memcgs a pass has already examined; waking, scheduling, reading
`memory.stat`, deciding and writing takes at least one full pass in a
burst, which is where the working set goes. The `low_request` hook sits at
the point where the request is collected, so it is asked *on* that pass.

### Arms

| Arm | Decision runs in | Evidence | Action |
|---|---|---|---|
| `user` | userspace thread | `memory.current` (the live page_counter) | `pwrite` the same sample to `memory.low` |
| `bpf-poll` | `bpf_wq` callback on a timer | the same page_counter via `bpf_mem_cgroup_usage()` | verdict stored in BSS, hook executes it |
| `bpf-hook` | inside `low_request`, at the collection point | the same page_counter via `ctx->usage`, per pass | the request itself |

`bpf-poll` is the control that isolates "the action runs in the kernel"
from "the decision runs at the decision point": it has kernel-grade action
latency but polled, tick-quantized evidence. `bpf-hook` is the only arm
that claims something userspace cannot do - decide on this pass's evidence
*inside* the pass that needs the decision, with no sampling lag at all.

All three run the *same* integer policy (`policy.h`: protect while the
evidence rate reaches a threshold, hold for a hysteresis, then drop) on the
*same* counter - A's `memory.current`, the page_counter the kernel charges
and uncharges synchronously - with the same threshold. The evidence is the
counter's *fall*: reclaim uncharges A in-pass, so a dropping usage means
"A is being stolen from" with no statistics-flush dependency; a rising
usage is A refaulting its own file and counts as nothing. The threshold is
a *rate* (pages per second) and each sample's fall is scaled by the time
since the previous sample, which keeps it arm-independent despite the
sampling-frequency spread: U/B1 sample on a fixed tick while B2 samples on
every protection pass (~10x more often during a reclaim storm), and a
per-sample threshold would silently demand a 10x higher evidence rate from
B2 - a calibration artifact, not a property of the arms. What differs is
only where the code runs and how fresh the sample is: U preads
`memory.current` from a timer/poll loop, B1 reads the same counter through
`bpf_mem_cgroup_usage()` on a wq tick, B2 reads it as `ctx->usage` - the
value the kernel itself read for this very pass - on every protection
pass.

Why the usage fall and not the textbook statistics: `workingset_refault`
only counts when the re-read still finds the shadow entry the eviction
left behind, and xarray nodes holding only shadows sit on the
`shadow_nodes` shrinker list, which B's churn runs on every one of its
thousands of reclaim passes per second - calibration measured 96M stolen
from A counting as 2 pages of refault (`pgmajfault` is similarly blind:
readahead and fault-around bypass its counting sites). `pgsteal` counts
the evictions themselves, but BPF can only read it from the flushed global
counters, and nothing flushes inside a reclaim pass (the flush kfunc is
sleepable; the hook is not): measured, an entire burst window passed with
the in-hook arm seeing zero `pgsteal` movement while A lost 19k pages.
`memory.current` is a live page_counter read with no flush in between, and
it is what the hook's ctx already carries. `pgsteal` and refaults remain
in the output as the window's outcome metrics, and the sanity gate is
still judged on A's `pgsteal`.

### Disclosures

- The U agent runs in its own cgroup with `memory.min = --agent-min`.
  Protecting the agent keeps it alive; it does not close the window, since
  the agent still only acts between passes. The B arms need no such
  protection - they run in kernel context.
- When protection is on, U writes the `memory.current` sample it just read
  to `memory.low` on every tick; the kernel-side `REQUEST_USAGE` re-reads
  A's usage on every pass. Same semantics, different staleness - the
  staleness and the rewrite cost are part of what the arm measures.
- The userspace arm is meant to be as good as it can be: pre-opened fds,
  `pread`/`pwrite`, no allocation in the loop, and the `--trigger poll`
  (PSI) option plus the 1/5/20/100ms timer sweep (`cmp-run.sh` phase 2,
  each point repeated `UCURVE_ROUNDS`=5 times and reported as per-point
  medians - single runs proved too noisy to order the points) exist to
  map its latency/CPU frontier instead of strawmanning it with one slow
  polling interval.
- The poll rows are expected to never fire on this workload, and that is
  a publishable negative result, not a bug: measured, the victim A stalls
  ~0.5ms/s - an order of magnitude below the 10ms/s trigger - while the
  filler B stalls 30-46ms/s. The cgroup being stolen from is the last
  place PSI-on-A can see it; usage fall is the right signal. (Without
  `psi=1` even this conclusion is unobservable - the columns read 0.)
- If `bpf-hook` does not separate from the best userspace arm on this
  workload, the honest conclusion is that userspace is enough here, and
  that result gets published too.

### Topology

```
/mnt                          private cgroup2 mount (setup_cgroup_environment)
+-- memcg_cmp_t        T: memory.max = --tmax (the pressure source),
                          memory.low = --budget, memory.swap.max = 0
    |-- a              A: paced re-reader (--read-cycle per pass); its pages
    |                     go cold between passes, so an unprotected A is
    |                     evicted by the proportional scan - every page lost
    |                     drops A's memory.current, the evidence every arm
    |                     triggers on, and shows up in A's pgsteal, the
    |                     window's outcome metric; hooks attach here
    |-- b              B: rewrites --filler of file cache every
    |                     --filler-sleep: a renewable flow of cold pages that
    |                     keeps satisfying T's reclaim while A is protected
    |-- c              C: --burst of anon, forked at window start; with
    |                     swap off it is unreclaimable ballast that shrinks
    |                     T's file pool, raising A's share of the scan
    +-- agent          the U arm's child (memory.min = --agent-min)
```

T is a direct child of the cgroup2 root on purpose: the reclaim triggered
by `T/memory.max` is rooted at T, and A rides the uncapped `parent == root`
fast path of `page_counter_calculate_protection()`; T's own `memory.low`
shields the subtree against system-wide reclaim. A workdir-relative
placement would interpose a cgroup with `memory.low == 0` and cap every
request to 0 under global reclaim - the `sanity` arm exists to prove the
chain works before any round counts.

### Metrics (per run, one CSV row)

Exact row columns, grouped:

| Group | Columns |
|---|---|
| config echo | `ts` (epoch s), `impl`, `trigger`, `interval_ms`, `psi_us`, `rate_pps` (the threshold), `read_cycle_ms`, `filler_sleep_ms`, `hysteresis_ms`, `duration_sec`, `burst`, `budget`, `tmax` |
| window outcome | `steal_a_pages` (primary), `refault_a_kib` (display), `low_a` (MEMCG_LOW overrides), `psi_a_us`, `psi_b_us`, `cur_a_kib` (A's usage at window end), `a_iters`, `a_avg_us`, `a_max_us` |
| trigger | `first_protect_ms` (`-1` = never engaged), `decisions`, `writes` (U arm), `hook_calls`, `requests`, `poll_ticks` (B1), `acquire_fails` |
| overhead | `run_time_ns` / `run_cnt` (attached hook), `agent_avg_us` / `agent_max_us` (U decision loop), `cpu_a_us`, `cpu_b_us`, `cpu_c_us`, `cpu_agent_us` (`cpu.stat` deltas) |
| validity | `valid` - `0` marks a ROUND VOID row, which stays out of the statistics |

Per-run report contents:

- **window**: A's `pgsteal` delta (the outcome metric), `workingset_refault_*`
  delta (display) and PSI `some total` delta across the burst phase; A's
  per-read avg/max latency.
- **time to first protection**, ms from burst start: U reports the instant
  its first protecting `memory.low` write returns; the B arms report the
  first pass whose request was granted (`cmp_first_request_ns`,
  `bpf_ktime_get_ns` - the same clock). A run where protection never
  engaged is flagged `valid=0` (**ROUND VOID**) and stays out of the
  statistics.
- **overhead**: attached hook `run_time_ns`/`run_cnt` deltas (needs
  `kernel.bpf_stats_enabled`, toggled by the tool), `cpu.stat`
  `usage_usec` deltas for A/B/C/agent, B1 poll ticks, B2 acquire-route
  failures, timer rearm failures.

Reading the numbers:

- **primary metric**: A's `pgsteal` delta per window, medians with IQR
  over >= 15 rounds. The formal 15-round run reached complete
  distribution separation - the in-hook arm's worst round beat both
  out-of-band arms' best rounds - which is the claim to headline.
- `first_protect_ms` is a **secondary** metric: under production pacing
  (A re-reading every 500ms, drains slow and episodic) it measures when
  the first threshold-crossing episode happened, not how fast the arm
  reacts inside an episode - the in-hook arm samples on every protection
  pass and fires in the episode's first pass whatever the timestamp says.
  Report medians; never rank arms by this column alone.
- A's `low` column counts kernel **soft-protection overrides** (the
  `MEMCG_LOW` event): times reclaim legally broke through granted
  `memory.low` protection because T's max could not be satisfied from
  unprotected supply. It is the explanatory variable for leak and
  read-tail outliers in any arm - including `sanity` - and marks the
  ceiling no `low_request` policy can exceed (`memory.min` is the hard
  guarantee, out of scope here).

### Protocol

`cmp-run.sh` implements it: per round a `sanity` gate (aborts on failure),
then the three arms in **rotating order**, `sync + drop_caches` between
runs, >= 15 rounds, all knobs identical across arms and rounds; phase 2
sweeps the U arm's trigger/interval frontier into the same CSV.
Everything lands in one timestamped run directory (`RUNDIR`):
`results.csv` plus `logs/` (per-run logs, environment, void list) - copy
that single directory between machines. The
sanity gate requests protection unconditionally, but still tolerates A
losing up to 1/8 of its file pages: C's charge storm occasionally cannot be
satisfied from B's young tail and dips through protection even when every
request is granted, so a zero-tolerance gate would abort on harmless leaks
while a broken chain (which loses A's whole working set per pass) still
fails it cleanly. Report
medians with IQR and publish the raw rows. Record the kernel build, swap
state (`/proc/swaps`) and boot config with the results -
`INIT_STACK_ALL_ZERO` and friends are part of the overhead numbers.

Calibrate (plan P0) before the first counted round: run each arm once,
verify all three engage protection promptly under the same burst
(`first_protect_ms` small, `valid=1`) *and* that an unprotected A visibly
loses pages (A's `pgsteal` grows during its passes and its read latency
blows up), then adjust `THRESHOLD` / `READ_CYCLE_MS` / `FILLER_SLEEP_MS` /
`PSI_US` until they do. Publish the calibrated values.

## Layout

| File | Role |
|---|---|
| `memcg_async_reclaim.bpf.c` | BPF side: timer/wq chain, refault trigger, reclaim rounds; cmp struct_ops hooks (`cmp_prot_ops_poll/hook/sanity`) |
| `memcg_async_reclaim_user.c` | CLI, bench harness, watch daemon, cmp harness and userspace agent |
| `memcg_async_reclaim.h` | shared config and ringbuf event structs |
| `policy.h` | the decision policy shared by all three cmp arms |
| `cmp-run.sh` | interleaved multi-round cmp runner with sanity gate |
| `cgroup_helpers.[ch]` | vendored from the kernel's selftests |
| `compat.h` | `READ_ONCE`/`WRITE_ONCE`/`__maybe_unused`/`ARRAY_SIZE` fallbacks |

## License

GPL-2.0, see [LICENSE](LICENSE).
