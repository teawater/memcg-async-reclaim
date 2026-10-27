// SPDX-License-Identifier: GPL-2.0
/*
 * memcg_async_reclaim - refault-driven asynchronous proactive reclaim
 *
 * A BPF program watches the workingset refaults of one cgroup and, whenever
 * they grow, reclaims from a second cgroup on a workqueue through
 * bpf_proactive_reclaim(). The monitored workload is never blocked: reclaim
 * runs asynchronously, in bounded batches, against somebody else's memory.
 *
 * Three modes:
 *
 *   bench   Create a high/low priority cgroup pair, run a memory-pressured
 *           workload in both, and report the effect on the pressured one. By
 *           default the same workload is first run without the BPF program to
 *           produce a baseline. Self-contained: creates and removes everything.
 *
 *   lowmin  Like bench, but protect a cgroup with the memory.low/memory.min
 *           BPF policy hooks (bpf_memcg_ops) instead of refault-driven reclaim:
 *           the parent is reclaimed under memory.max and the hook keeps the
 *           protected child's cache hot. Configurable to use low or min.
 *
 *   watch   Watch an existing cgroup given by path and keep reclaiming from
 *           another one for as long as the program runs, or protect the watched
 *           one with the memory.low/memory.min BPF policy hooks instead of
 *           reclaiming; --observe and --control pick the methods. Removing the
 *           target while it runs is handled: reclaim stops and the events say so.
 *
 * All modes need root.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"
#include "compat.h"
#include "memcg_async_reclaim.h"
#include "memcg_async_reclaim.skel.h"

/*
 * The bench workload lasts tens of milliseconds, so its tick has to be far
 * shorter than that to catch any refaults at all. A daemon has no such
 * constraint, and a short tick means a stat flush per tick against the
 * monitored cgroup, so watch defaults to something production-shaped.
 */
#define BENCH_INTERVAL_MS	2
#define WATCH_INTERVAL_MS	20

#define DEFAULT_THRESHOLD	1
#define DEFAULT_BATCH_BYTES	(128 * 1024UL)
#define DEFAULT_MAX_BATCHES	32
#define DEFAULT_SWAPPINESS	(-1L)
#define DEFAULT_STATS_SEC	10

#define DEFAULT_CG_LIMIT	(32 * 1024 * 1024UL)
#define DEFAULT_FILE_SIZE	(32 * 1024 * 1024UL)
#define DEFAULT_READ_TIMES	50UL
#define WRITE_BUFFER_SIZE	4096

#define BENCH_CG_DIR		"/memcg_async_reclaim"
#define BENCH_CG_HIGH_DIR	BENCH_CG_DIR "/high"
#define BENCH_CG_LOW_DIR	BENCH_CG_DIR "/low"

#define LOWMIN_CG_DIR		"/memcg_lowmin"
#define LOWMIN_CG_PROT_DIR	LOWMIN_CG_DIR "/prot"
#define LOWMIN_CG_VICTIM_DIR	LOWMIN_CG_DIR "/victim"

/* How long a single ring_buffer__poll() blocks while waiting for a signal. */
#define POLL_SLICE_MS		200

/* Which protection hook asserts BELOW in lowmin mode. */
enum protect_level {
	LEVEL_MIN = 0,	/* default: hard memory.min protection */
	LEVEL_LOW,
	LEVEL_BOTH,
};

struct options {
	/* shared */
	unsigned long interval_ms;	/* 0 means "use the mode's default" */
	unsigned long threshold;
	unsigned long batch_bytes;
	unsigned long max_batches;
	long swappiness;
	bool verbose;
	/* bench */
	unsigned long cg_limit;
	unsigned long file_size;
	unsigned long read_times;
	bool no_baseline;
	/* watch */
	const char *monitor_path;
	const char *target_path;
	unsigned long duration_sec;
	unsigned long stats_sec;
	unsigned int observe_mask;	/* OBS_* bits */
	unsigned int control_mask;	/* CTL_* bits */
	/* lowmin (reuses cg_limit/file_size/read_times/no_baseline above) */
	int prot_level;		/* enum protect_level */
	bool level_given;	/* -L seen; watch expresses the same via --control */
	bool events;
};

struct counters {
	unsigned long long rounds;
	unsigned long long calls;
	unsigned long long bytes;
	unsigned long long below;
};

struct session {
	struct memcg_async_reclaim *skel;
	struct ring_buffer *rb;
	/* watch_prot_ops attached to the monitor cgroup; NULL when not protecting. */
	struct bpf_link *watch_link;
	/* The cgroup fd the link was attached with, kept open for the link's life. */
	int mon_fd;
	/* Whether the timer/wq reclaim engine was started (--control reclaim). */
	bool reclaim;
	bool verbose;
	double start;
	unsigned long long called;
	unsigned long long skipped_dying;
	unsigned long long target_gone;
	struct counters last;
};

/* Set by the signal handler, polled with READ_ONCE() in the main loops. */
static sig_atomic_t exiting;

static void handle_signal(__maybe_unused int sig)
{
	WRITE_ONCE(exiting, 1);
}

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int parse_ulong(const char *s, unsigned long *out)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s || *end)
		return -1;

	*out = v;

	return 0;
}

static int parse_long(const char *s, long *out)
{
	long v;
	char *end;

	errno = 0;
	v = strtol(s, &end, 0);
	if (errno || end == s || *end)
		return -1;

	*out = v;

	return 0;
}

/* Accepts a plain byte count or one suffixed with K, M or G. */
static int parse_size(const char *s, unsigned long *out)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s)
		return -1;

	switch (*end) {
	case 'k':
	case 'K':
		v <<= 10;
		end++;
		break;
	case 'm':
	case 'M':
		v <<= 20;
		end++;
		break;
	case 'g':
	case 'G':
		v <<= 30;
		end++;
		break;
	case '\0':
		break;
	default:
		return -1;
	}

	if (*end)
		return -1;

	*out = v;

	return 0;
}

/* watch mode method names, one table per selector. */
struct method_name {
	const char *name;
	unsigned int bit;
};

static const struct method_name observe_methods[] = {
	{ "refault",	OBS_REFAULT },
	{ "low",	OBS_LOW },
	{ "min",	OBS_MIN },
};

static const struct method_name control_methods[] = {
	{ "reclaim",	CTL_RECLAIM },
	{ "low",	CTL_LOW },
	{ "min",	CTL_MIN },
};

/*
 * Parse a comma-separated method list into a bitmask. Repeating the option
 * accumulates, so "--control reclaim,min" and "--control reclaim --control min"
 * mean the same thing. arg is copied because strsep() NUL-terminates in place
 * and optarg belongs to argv.
 *
 * An empty list is an error rather than "keep the default": otherwise
 * --observe "" would silently leave the previous value in place. For the same
 * reason the caller leaves the mask at 0 and applies the default only after
 * parsing - seeding it here would make "--control min" mean "reclaim,min".
 */
static int parse_methods(const char *arg, unsigned int *mask,
			 const struct method_name *tab, size_t n,
			 const char *opt)
{
	char buf[64], *p = buf, *tok;
	size_t len = strlen(arg);
	unsigned int got = 0;
	size_t i;

	if (len >= sizeof(buf)) {
		fprintf(stderr, "ERROR: %s: list too long\n", opt);
		return -1;
	}
	memcpy(buf, arg, len + 1);

	while ((tok = strsep(&p, ",")) != NULL) {
		if (!*tok)
			continue;	/* an empty field, e.g. a trailing comma */
		for (i = 0; i < n; i++)
			if (!strcmp(tok, tab[i].name))
				break;
		if (i == n) {
			fprintf(stderr, "ERROR: %s: unknown method '%s', expected",
				opt, tok);
			for (i = 0; i < n; i++)
				fprintf(stderr, "%s %s", i ? "," : "",
					tab[i].name);
			fprintf(stderr, " (combine several with ',')\n");
			return -1;
		}
		got |= tab[i].bit;
	}

	if (!got) {
		fprintf(stderr, "ERROR: %s: no method given\n", opt);
		return -1;
	}

	*mask |= got;

	return 0;
}

/* Render a mask back into the same comma-separated form, for the banner. */
static void fmt_methods(char *buf, size_t len, unsigned int mask,
			const struct method_name *tab, size_t n)
{
	size_t i, off = 0;

	buf[0] = '\0';
	for (i = 0; i < n && off < len; i++)
		if (mask & tab[i].bit)
			off += snprintf(buf + off, len - off, "%s%s",
					off ? "," : "", tab[i].name);
}

static void fmt_bytes(char *buf, size_t len, unsigned long long bytes)
{
	if (bytes >= (1ULL << 30))
		snprintf(buf, len, "%.1f GiB", bytes / (double)(1ULL << 30));
	else if (bytes >= (1ULL << 20))
		snprintf(buf, len, "%.1f MiB", bytes / (double)(1ULL << 20));
	else if (bytes >= (1ULL << 10))
		snprintf(buf, len, "%.1f KiB", bytes / (double)(1ULL << 10));
	else
		snprintf(buf, len, "%llu B", bytes);
}

static const char *outcome_str(__u64 outcome)
{
	switch (outcome) {
	case RECLAIM_OUTCOME_CALLED:
		return "called";
	case RECLAIM_OUTCOME_SKIPPED_DYING:
		return "skipped-dying";
	case RECLAIM_OUTCOME_TARGET_GONE:
		return "target-gone";
	default:
		return "unknown";
	}
}

/* session code */

static int on_reclaim_event(void *ctx, void *data, size_t sz)
{
	struct session *s = ctx;
	const struct reclaim_event *ev = data;

	if (sz < sizeof(*ev))
		return 0;

	switch (ev->outcome) {
	case RECLAIM_OUTCOME_CALLED:
		s->called++;
		break;
	case RECLAIM_OUTCOME_SKIPPED_DYING:
		s->skipped_dying++;
		break;
	case RECLAIM_OUTCOME_TARGET_GONE:
		s->target_gone++;
		break;
	}

	if (s->verbose)
		printf("[%7.3fs] event %-13s called=%llu dying=%llu gone=%llu\n",
		       now_sec() - s->start, outcome_str(ev->outcome),
		       s->called, s->skipped_dying, s->target_gone);

	return 0;
}

static void read_counters(struct session *s, struct counters *c)
{
	c->rounds = s->skel->bss->reclaim_rounds;
	c->calls = s->skel->bss->reclaim_calls;
	c->bytes = s->skel->bss->reclaimed_bytes;
	c->below = s->skel->bss->watch_below_cnt;
}

static int session_start(struct session *s, const struct options *o,
			 __u64 monitor_id, __u64 target_id)
{
	struct reclaim_cfg cfg = {
		.monitor_cgroup_id = monitor_id,
		.target_cgroup_id = target_id,
		.refault_threshold = o->threshold,
		.interval_ns = (unsigned long long)o->interval_ms * 1000000ULL,
		.batch_bytes = o->batch_bytes,
		.max_batches = o->max_batches,
		.swappiness = o->swappiness,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		    .ctx_in = &cfg,
		    .ctx_size_in = sizeof(cfg));
	bool reclaim = o->control_mask & CTL_RECLAIM;
	bool protect = o->control_mask & (CTL_LOW | CTL_MIN);
	int init_fd, err;

	s->verbose = o->verbose;
	s->mon_fd = -1;
	s->reclaim = reclaim;
	s->start = now_sec();

	s->skel = memcg_async_reclaim__open();
	if (!s->skel) {
		fprintf(stderr, "ERROR: failed to open the BPF object\n");
		return -1;
	}

	/*
	 * The hooks read their configuration from .bss on every call, so it has
	 * to be in place before load; there is no map to update afterwards.
	 */
	if (protect) {
		s->skel->bss->watch_mon_id = monitor_id;
		s->skel->bss->watch_control = o->control_mask;
	}

	if (memcg_async_reclaim__load(s->skel)) {
		fprintf(stderr, "ERROR: failed to load the BPF object\n");
		goto err_out;
	}

	/*
	 * One link, on the monitor cgroup, covers every --control combination:
	 * both hooks are bound at load time and watch_control picks which one
	 * answers BELOW. The fd has to stay open for the link's lifetime.
	 */
	if (protect) {
		s->mon_fd = open(o->monitor_path, O_RDONLY | O_CLOEXEC);
		if (s->mon_fd < 0) {
			fprintf(stderr, "ERROR: cannot open %s: %s\n",
				o->monitor_path, strerror(errno));
			goto err_out;
		}

		s->watch_link = bpf_map__attach_cgroup_opts(s->skel->maps.watch_prot_ops,
							    s->mon_fd, NULL);
		if (!s->watch_link) {
			fprintf(stderr, "ERROR: failed to attach the policy to %s: %s\n",
				o->monitor_path, strerror(errno));
			goto err_out;
		}
	}

	/*
	 * The syscall program installs the timer and the work item into the
	 * map and starts the timer; from then on the chain runs on its own.
	 * Without --control reclaim there is no target and nothing to drive.
	 */
	if (reclaim) {
		init_fd = bpf_program__fd(s->skel->progs.reclaim_prog_init);
		err = bpf_prog_test_run_opts(init_fd, &run_opts);
		if (err || run_opts.retval) {
			fprintf(stderr, "ERROR: reclaim_prog_init failed: %s (retval %d)\n",
				err ? strerror(errno) : "rejected by the program",
				run_opts.retval);
			goto err_out;
		}
	}

	s->rb = ring_buffer__new(bpf_map__fd(s->skel->maps.reclaim_events),
				 on_reclaim_event, s, NULL);
	if (!s->rb) {
		fprintf(stderr, "ERROR: failed to create the ring buffer\n");
		goto err_out;
	}

	read_counters(s, &s->last);

	return 0;

err_out:
	bpf_link__destroy(s->watch_link);
	s->watch_link = NULL;
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;
	if (s->mon_fd >= 0) {
		close(s->mon_fd);
		s->mon_fd = -1;
	}

	return -1;
}

/* Poll until the timeout expires; returns early on a signal or an error. */
static int session_poll(struct session *s, int timeout_ms)
{
	int deadline_ms = timeout_ms, n;

	while (!READ_ONCE(exiting) && deadline_ms > 0) {
		int slice = deadline_ms > POLL_SLICE_MS ? POLL_SLICE_MS
							 : deadline_ms;

		n = ring_buffer__poll(s->rb, slice);
		/* A signal interrupts epoll_wait(), which is how we stop. */
		if (n < 0 && n != -EINTR)
			return -1;

		deadline_ms -= slice;
	}

	return 0;
}

static void print_counters(struct session *s, const char *prefix)
{
	struct counters now;
	char bytes[32], delta[32];

	read_counters(s, &now);
	fmt_bytes(bytes, sizeof(bytes), now.bytes);
	fmt_bytes(delta, sizeof(delta), now.bytes - s->last.bytes);

	printf("%s rounds=%llu(+%llu) calls=%llu(+%llu) reclaimed=%s(+%s)",
	       prefix, now.rounds, now.rounds - s->last.rounds,
	       now.calls, now.calls - s->last.calls, bytes, delta);
	/* below only moves when the policy is attached; printing 0 forever is noise. */
	if (s->watch_link)
		printf(" below=%llu(+%llu)", now.below, now.below - s->last.below);
	printf("\n");

	s->last = now;
}

static void session_stop(struct session *s)
{
	unsigned long long failures, last_err;

	if (!s->skel)
		return;

	ring_buffer__free(s->rb);
	s->rb = NULL;

	failures = s->skel->bss->timer_failures;
	last_err = s->skel->bss->last_reclaim_err;

	printf("\nran for %.1fs\n", now_sec() - s->start);
	print_counters(s, "total:");
	if (s->reclaim)
		printf("events: called=%llu skipped_dying=%llu target_gone=%llu\n",
		       s->called, s->skipped_dying, s->target_gone);
	if (failures)
		printf("WARNING: monitor timer rearm failed %llu time(s), reclaim stopped early\n",
		       failures);
	if (last_err)
		printf("WARNING: bpf_proactive_reclaim() last failed with -%llu\n",
		       last_err);

	/* The link pins the map, so it has to go before the skeleton does. */
	bpf_link__destroy(s->watch_link);
	s->watch_link = NULL;

	/* Destroying the skeleton drops the map, which cancels timer and wq. */
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;

	if (s->mon_fd >= 0) {
		close(s->mon_fd);
		s->mon_fd = -1;
	}
}

/* watch mode setup code */

/*
 * cgroup_helpers' get_cgroup_id() resolves paths relative to the private
 * hierarchy it mounts for the bench mode, so watch mode needs its own lookup
 * against the paths the user gave. cgroupfs file handles are always 8 bytes
 * and hold the cgroup id, so there is no need for the two-call size probe.
 */
static __u64 cgroup_id_from_path(const char *path)
{
	struct {
		struct file_handle fh;
		__u64 cgid;
	} h = {};
	int mnt_id;

	h.fh.handle_bytes = sizeof(h.cgid);

	if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mnt_id, 0))
		return 0;
	/*
	 * Only the size is checked, not handle_type: cgroupfs encodes through
	 * kernfs_encode_fh(), whose FILEID_KERNFS is not visible to userspace.
	 */
	if (h.fh.handle_bytes != sizeof(h.cgid))
		return 0;

	return h.cgid;
}

static bool memcg_on_path(const char *path)
{
	char file[PATH_MAX];
	int fd;

	snprintf(file, sizeof(file), "%s/memory.current", path);
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return false;
	close(fd);

	return true;
}

/* Resolve a user-supplied cgroup path and check the memory controller is on. */
static int resolve_memcg(const char *path, __u64 *id)
{
	*id = cgroup_id_from_path(path);
	if (!*id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", path,
			strerror(errno));
		return -1;
	}

	if (!memcg_on_path(path)) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory\n"
			"       controller is not enabled on that cgroup.\n",
			path);
		return -1;
	}

	return 0;
}

/* bench mode code */

/*
 * The workload files must sit on a regular filesystem: with swap disabled for
 * the cgroup, tmpfs pages are unevictable and would OOM the cgroup instead of
 * exercising reclaim; they are also charged as shmem rather than as the page
 * cache this workload is meant to build, so they never raise the workingset
 * refaults the BPF program watches.
 *
 * /tmp is tmpfs on many systems, so fall back to the current directory. That
 * fallback needs the same check: both directories are tmpfs more often than
 * not. Writability is checked too: a read-only mount cannot host the files
 * at all, and EROFS applies to root as well.
 */
static const char *workload_files_dir(void)
{
	static const char * const dirs[] = { "/tmp", "." };
	struct statfs st;
	int i;

	for (i = 0; i < 2; i++)
		if (!statfs(dirs[i], &st) && st.f_type != TMPFS_MAGIC &&
		    st.f_type != RAMFS_MAGIC && !access(dirs[i], W_OK))
			return dirs[i];

	return NULL;
}

/*
 * Keep the workload from swapping out, so that reclaim has to evict page cache.
 * memory.swap.max only exists when the kernel is built with CONFIG_SWAP, and
 * /proc/swaps is registered by the same CONFIG_SWAP-gated code (mm/swapfile.c),
 * so it stands in for the config here.
 */
static int disable_swap(const char *cgroup_dir)
{
	if (access("/proc/swaps", F_OK))
		return 0;

	return write_cgroup_file(cgroup_dir, "memory.swap.max", "0");
}

static int setup_bench_cgroups(const struct options *o, __u64 *high_id,
			       __u64 *low_id)
{
	char limit_buf[32];
	int fd;

	if (setup_cgroup_environment()) {
		fprintf(stderr, "ERROR: failed to set up the cgroup environment\n");
		return -1;
	}

	fd = create_and_get_cgroup(BENCH_CG_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	if (enable_controllers(BENCH_CG_DIR, "memory"))
		goto err;

	snprintf(limit_buf, sizeof(limit_buf), "%lu", o->cg_limit);
	if (write_cgroup_file(BENCH_CG_DIR, "memory.max", limit_buf))
		goto err;
	if (disable_swap(BENCH_CG_DIR))
		goto err;

	fd = create_and_get_cgroup(BENCH_CG_HIGH_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	fd = create_and_get_cgroup(BENCH_CG_LOW_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	*high_id = get_cgroup_id(BENCH_CG_HIGH_DIR);
	*low_id = get_cgroup_id(BENCH_CG_LOW_DIR);
	if (!*high_id || !*low_id) {
		fprintf(stderr, "ERROR: failed to read the cgroup ids\n");
		goto err;
	}

	return 0;

err:
	cleanup_cgroup_environment();

	return -1;
}

/*
 * The forked children cannot report through stdio, so the exit status is the
 * one diagnostics channel that reliably reaches the parent: each failing step
 * gets its own code.
 */
enum child_exit_code {
	CHILD_EXIT_OK = 0,
	CHILD_EXIT_JOIN_CGROUP,
	CHILD_EXIT_WRITE_FILE,
	CHILD_EXIT_READ_FILE,
	CHILD_EXIT_TIME_FILE,
};

static const char *child_exit_str(int code)
{
	switch (code) {
	case CHILD_EXIT_OK:
		return "success";
	case CHILD_EXIT_JOIN_CGROUP:
		return "join cgroup";
	case CHILD_EXIT_WRITE_FILE:
		return "write data file";
	case CHILD_EXIT_READ_FILE:
		return "read data file";
	case CHILD_EXIT_TIME_FILE:
		return "write time file";
	default:
		return "unknown";
	}
}

static int write_file(int fd, unsigned long file_size)
{
	char *buffer;
	size_t written = 0;

	buffer = malloc(WRITE_BUFFER_SIZE);
	if (!buffer)
		return -1;

	memset(buffer, 'A', WRITE_BUFFER_SIZE);

	while (written < file_size) {
		size_t to_write = file_size - written < WRITE_BUFFER_SIZE ?
				  file_size - written : WRITE_BUFFER_SIZE;
		ssize_t n = write(fd, buffer, to_write);

		if (n <= 0) {
			free(buffer);
			return -1;
		}
		written += n;
	}

	free(buffer);

	return 0;
}

static int read_file(int fd, unsigned long file_size, unsigned long iterations)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long i, iter;
	struct stat sb;
	char *map;

	if (fstat(fd, &sb) || (unsigned long)sb.st_size != file_size)
		return -1;

	map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		return -1;

	for (iter = 0; iter < iterations; iter++)
		for (i = 0; i < file_size; i += page_size)
			/* touch a byte per page to trigger the fault */
			(void)READ_ONCE(map[i]);

	return munmap(map, file_size) ? -1 : 0;
}

static int child_work(const char *cgroup_path, int data_fd, int time_fd,
		      const struct options *o)
{
	struct timespec start, end;
	char buf[32];
	double elapsed;
	int len;

	if (join_parent_cgroup(cgroup_path))
		return CHILD_EXIT_JOIN_CGROUP;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (write_file(data_fd, o->file_size))
		return CHILD_EXIT_WRITE_FILE;
	if (read_file(data_fd, o->file_size, o->read_times))
		return CHILD_EXIT_READ_FILE;

	clock_gettime(CLOCK_MONOTONIC, &end);

	elapsed = (end.tv_sec - start.tv_sec) +
		  (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	len = snprintf(buf, sizeof(buf), "%.6f", elapsed);
	/* snprintf() returns the untruncated length, so bound it before write() */
	if (len < 0 || len >= (int)sizeof(buf) || write(time_fd, buf, len) != len)
		return CHILD_EXIT_TIME_FILE;

	return CHILD_EXIT_OK;
}

static int get_time(int fd, double *elapsed)
{
	char buf[64] = {};
	ssize_t n;

	/* The child wrote through the fork-shared description, so rewind. */
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "ERROR: lseek time file: %s\n", strerror(errno));
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "ERROR: read time file: %s\n", strerror(errno));
		return -1;
	}

	if (sscanf(buf, "%lf", elapsed) != 1) {
		fprintf(stderr, "ERROR: cannot parse time '%s'\n", buf);
		return -1;
	}

	return 0;
}

/*
 * Reap one workload child and turn its exit code into a diagnostic. @pid is
 * cleared on every path, including failure: once the child has been reaped its
 * PID can be reused, and the error path signals whatever is left in it.
 */
static int reap_child(pid_t *pid, const char *who)
{
	int status;

	if (waitpid(*pid, &status, 0) <= 0) {
		fprintf(stderr, "ERROR: waitpid %s: %s\n", who, strerror(errno));
		*pid = -1;
		return -1;
	}
	*pid = -1;

	if (!WIFEXITED(status)) {
		fprintf(stderr, "ERROR: %s child died, status 0x%x\n", who, status);
		return -1;
	}
	if (WEXITSTATUS(status) != CHILD_EXIT_OK) {
		fprintf(stderr, "ERROR: %s child failed at: %s (exit status %d)\n",
			who, child_exit_str(WEXITSTATUS(status)),
			WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

/*
 * Run the workload in two cgroups at the same time and report how long each
 * took. The two paths name the cgroups to join: bench passes its high/low pair,
 * lowmin passes its prot/victim pair. The "high" slot is the primary cgroup
 * (the protected one), the "low" slot the secondary (the reclaimed one).
 */
static int run_workload(const char *dir, const char *high_path,
			const char *low_path, const struct options *o,
			double *high_elapsed, double *low_elapsed)
{
	char high_data[PATH_MAX], low_data[PATH_MAX];
	char high_time[PATH_MAX], low_time[PATH_MAX];
	int high_data_fd = -1, low_data_fd = -1;
	int high_time_fd = -1, low_time_fd = -1;
	pid_t high_pid = -1, low_pid = -1;
	int ret = -1;

	snprintf(high_data, sizeof(high_data), "%s/memcg_high_data_XXXXXX", dir);
	snprintf(low_data, sizeof(low_data), "%s/memcg_low_data_XXXXXX", dir);
	snprintf(high_time, sizeof(high_time), "%s/memcg_high_time_XXXXXX", dir);
	snprintf(low_time, sizeof(low_time), "%s/memcg_low_time_XXXXXX", dir);

	/*
	 * The mkstemp() fds are kept and inherited by the children rather than
	 * reopened by name: reopening would resolve the path again and follow
	 * whatever sits there by then.
	 */
	high_data_fd = mkstemp(high_data);
	low_data_fd = mkstemp(low_data);
	high_time_fd = mkstemp(high_time);
	low_time_fd = mkstemp(low_time);
	if (high_data_fd < 0 || low_data_fd < 0 || high_time_fd < 0 ||
	    low_time_fd < 0) {
		fprintf(stderr, "ERROR: mkstemp: %s\n", strerror(errno));
		goto cleanup;
	}

	low_pid = fork();
	if (low_pid < 0) {
		fprintf(stderr, "ERROR: fork low: %s\n", strerror(errno));
		goto cleanup;
	}
	if (low_pid == 0)
		_exit(child_work(low_path, low_data_fd, low_time_fd, o));

	high_pid = fork();
	if (high_pid < 0) {
		fprintf(stderr, "ERROR: fork high: %s\n", strerror(errno));
		goto cleanup;
	}
	if (high_pid == 0)
		_exit(child_work(high_path, high_data_fd, high_time_fd, o));

	if (reap_child(&low_pid, "low"))
		goto cleanup;
	if (reap_child(&high_pid, "high"))
		goto cleanup;

	if (get_time(high_time_fd, high_elapsed))
		goto cleanup;
	if (get_time(low_time_fd, low_elapsed))
		goto cleanup;

	ret = 0;

cleanup:
	/* On failure, make sure no child process is left behind. */
	if (ret) {
		if (high_pid > 0) {
			kill(high_pid, SIGKILL);
			waitpid(high_pid, NULL, 0);
		}
		if (low_pid > 0) {
			kill(low_pid, SIGKILL);
			waitpid(low_pid, NULL, 0);
		}
	}
	if (high_data_fd >= 0)
		close(high_data_fd);
	if (low_data_fd >= 0)
		close(low_data_fd);
	if (high_time_fd >= 0)
		close(high_time_fd);
	if (low_time_fd >= 0)
		close(low_time_fd);
	unlink(high_data);
	unlink(low_data);
	unlink(high_time);
	unlink(low_time);

	return ret;
}

static void print_speedup(const char *who, double baseline, double measured)
{
	if (baseline <= 0.0)
		return;

	printf("%s: baseline=%.3fs reclaim=%.3fs speedup=%+.1f%%\n", who,
	       baseline, measured,
	       100.0 * (baseline - measured) / baseline);
}

static int do_bench(struct options *o)
{
	double base_high = 0.0, base_low = 0.0;
	double high = 0.0, low = 0.0;
	struct session s = {};
	__u64 high_id, low_id;
	const char *dir;
	int ret = 1;

	dir = workload_files_dir();
	if (!dir) {
		fprintf(stderr, "ERROR: neither /tmp nor the working directory is on a\n"
			"       writable regular filesystem; the workload needs one\n"
			"       because tmpfs pages are not reclaimable without swap.\n");
		return 1;
	}

	if (setup_bench_cgroups(o, &high_id, &low_id))
		return 1;

	if (!o->no_baseline) {
		printf("baseline run (no BPF program)...\n");
		if (run_workload(dir, BENCH_CG_HIGH_DIR, BENCH_CG_LOW_DIR, o,
				 &base_high, &base_low))
			goto out;

		/*
		 * The baseline left up to cg_limit of page cache charged to the
		 * two cgroups, and memcg charges outlive the workload processes.
		 * Recreate the cgroups so that the instrumented run starts from
		 * the same cold state; otherwise the reported speedup compares a
		 * cold run against a warm one.
		 */
		cleanup_cgroup_environment();
		if (setup_bench_cgroups(o, &high_id, &low_id))
			return 1;
	}

	if (session_start(&s, o, high_id, low_id))
		goto out;

	printf("reclaim run (BPF program active)...\n");
	if (run_workload(dir, BENCH_CG_HIGH_DIR, BENCH_CG_LOW_DIR, o,
			 &high, &low))
		goto out;

	printf("\nworkload: file_size=%lu read_times=%lu memory.max=%lu\n",
	       o->file_size, o->read_times, o->cg_limit);
	printf("high priority: %.3fs   low priority: %.3fs\n", high, low);
	if (!o->no_baseline) {
		print_speedup("high", base_high, high);
		print_speedup("low", base_low, low);
	}

	ret = 0;

out:
	session_stop(&s);
	cleanup_cgroup_environment();

	return ret;
}

/* lowmin mode code */

/*
 * Set up the lowmin topology: a parent with memory.max and swap off, plus a
 * protected child (prot) and a victim child (victim). Returns prot's id and an
 * open fd to prot, which bpf_map__attach_cgroup_opts() needs and which is later
 * reused to read prot's memory.events. The caller closes prot_fd and tears the
 * environment down.
 */
static int setup_lowmin_cgroups(const struct options *o, __u64 *prot_id,
				int *prot_fd)
{
	char limit_buf[32];
	int fd;

	*prot_fd = -1;

	if (setup_cgroup_environment()) {
		fprintf(stderr, "ERROR: failed to set up the cgroup environment\n");
		return -1;
	}

	fd = create_and_get_cgroup(LOWMIN_CG_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	if (enable_controllers(LOWMIN_CG_DIR, "memory"))
		goto err;

	snprintf(limit_buf, sizeof(limit_buf), "%lu", o->cg_limit);
	if (write_cgroup_file(LOWMIN_CG_DIR, "memory.max", limit_buf))
		goto err;
	if (disable_swap(LOWMIN_CG_DIR))
		goto err;

	fd = create_and_get_cgroup(LOWMIN_CG_VICTIM_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	/* Keep prot's fd open: needed to attach the ops and to read events. */
	*prot_fd = create_and_get_cgroup(LOWMIN_CG_PROT_DIR);
	if (*prot_fd < 0)
		goto err;

	*prot_id = get_cgroup_id(LOWMIN_CG_PROT_DIR);
	if (!*prot_id) {
		fprintf(stderr, "ERROR: failed to read the prot cgroup id\n");
		goto err;
	}

	return 0;

err:
	if (*prot_fd >= 0)
		close(*prot_fd);
	*prot_fd = -1;
	cleanup_cgroup_environment();

	return -1;
}

/* Read one "key value" line from a cgroup file via an open cgroup dir fd. */
static int read_cgroup_event_fd(int cgfd, const char *file, const char *key,
				unsigned long *out)
{
	char line[128], k[64];
	unsigned long v;
	int fd, found = 0;
	FILE *fp;

	fd = openat(cgfd, file, O_RDONLY);
	if (fd < 0)
		return -1;

	fp = fdopen(fd, "r");
	if (!fp) {
		close(fd);
		return -1;
	}

	while (fgets(line, sizeof(line), fp))
		if (sscanf(line, "%63s %lu", k, &v) == 2 && !strcmp(k, key)) {
			*out = v;
			found = 1;
			break;
		}

	fclose(fp);	/* also closes fd */

	return found ? 0 : -1;
}

static struct bpf_link *attach_prot_ops(struct memcg_async_reclaim *skel,
					int prot_fd)
{
	struct bpf_link *link;

	link = bpf_map__attach_cgroup_opts(skel->maps.prot_ops, prot_fd, NULL);
	if (!link)
		fprintf(stderr, "ERROR: failed to attach the protection ops: %s\n",
			strerror(errno));

	return link;
}

static const char *level_str(int level)
{
	switch (level) {
	case LEVEL_LOW:
		return "low";
	case LEVEL_BOTH:
		return "both";
	default:
		return "min";
	}
}

static int do_lowmin(struct options *o)
{
	double base_prot = 0.0, base_victim = 0.0;
	double prot_t = 0.0, victim_t = 0.0;
	struct memcg_async_reclaim *skel = NULL;
	struct bpf_link *link = NULL;
	int assert_low, assert_min;
	__u64 prot_id = 0;
	int prot_fd = -1;
	const char *dir;
	int ret = 1;

	dir = workload_files_dir();
	if (!dir) {
		fprintf(stderr, "ERROR: neither /tmp nor the working directory is on a\n"
			"       writable regular filesystem; the workload needs one\n"
			"       because tmpfs pages are not reclaimable without swap.\n");
		return 1;
	}

	assert_low = (o->prot_level == LEVEL_LOW || o->prot_level == LEVEL_BOTH);
	assert_min = (o->prot_level == LEVEL_MIN || o->prot_level == LEVEL_BOTH);

	/*
	 * Safety net for an explicit -f (the per-level defaults are sized in
	 * main()). Under hard min protection 'prot' is immune to reclaim, so if
	 * its fill could reach the whole parent limit, 'victim' is left nothing
	 * reclaimable and the memcg OOMs; shrink it below the limit. low is soft
	 * and cannot OOM, but staying below the limit also keeps 'prot' from
	 * being breached. Reclaim only happens once the two children together
	 * exceed the limit, so warn when they would both fit and there is
	 * nothing to show.
	 */
	if (o->file_size >= o->cg_limit) {
		o->file_size = o->cg_limit / 4 * 3;
		printf("note: --file-size >= --limit; using file-size=%luM so the protected\n"
		       "      'prot' cannot fill the parent and OOM 'victim'\n",
		       o->file_size / (1024 * 1024));
	}
	if (2 * o->file_size <= o->cg_limit)
		printf("note: 2 * file-size <= limit; both children fit under the parent,\n"
		       "      so little is reclaimed and the effect may be small\n");

	printf("lowmin: parent=%s (max=%luM) prot=prot victim=victim level=%s fill=%luM\n",
	       LOWMIN_CG_DIR, o->cg_limit / (1024 * 1024), level_str(o->prot_level),
	       o->file_size / (1024 * 1024));

	/* Baseline: the same workload with no protection attached. */
	if (!o->no_baseline) {
		if (setup_lowmin_cgroups(o, &prot_id, &prot_fd))
			return 1;

		printf("baseline run (no ops)...\n");
		if (run_workload(dir, LOWMIN_CG_PROT_DIR, LOWMIN_CG_VICTIM_DIR,
				 o, &base_prot, &base_victim))
			goto out;

		/* Reset to a cold state, as bench does between its two runs. */
		close(prot_fd);
		prot_fd = -1;
		cleanup_cgroup_environment();
	}

	/* Protected: load the policy, attach it to prot, run the workload again. */
	if (setup_lowmin_cgroups(o, &prot_id, &prot_fd))
		return 1;

	skel = memcg_async_reclaim__open();
	if (!skel) {
		fprintf(stderr, "ERROR: failed to open the BPF object\n");
		goto out;
	}

	/* Set the policy globals before load, like the kernel selftest does. */
	skel->bss->prot_cgroup_id = prot_id;
	skel->bss->prot_assert_low = assert_low;
	skel->bss->prot_assert_min = assert_min;

	if (memcg_async_reclaim__load(skel)) {
		fprintf(stderr, "ERROR: failed to load the BPF object\n");
		goto out;
	}

	link = attach_prot_ops(skel, prot_fd);
	if (!link)
		goto out;

	printf("protected run (ops on prot, %s BELOW)...\n", level_str(o->prot_level));
	if (run_workload(dir, LOWMIN_CG_PROT_DIR, LOWMIN_CG_VICTIM_DIR,
			 o, &prot_t, &victim_t))
		goto out;

	printf("  prot_low_calls=%llu prot_min_calls=%llu last_usage=%llu pages last_threshold=%llu\n",
	       (unsigned long long)skel->bss->prot_low_calls,
	       (unsigned long long)skel->bss->prot_min_calls,
	       (unsigned long long)skel->bss->prot_last_usage,
	       (unsigned long long)skel->bss->prot_last_threshold);

	if (o->events) {
		unsigned long ev_low = 0;

		if (!read_cgroup_event_fd(prot_fd, "memory.events", "low", &ev_low))
			printf("  prot memory.events low=%lu\n", ev_low);
		else
			fprintf(stderr, "WARNING: cannot read prot memory.events\n");
	}

	printf("\nworkload: file_size=%lu read_times=%lu memory.max=%lu\n",
	       o->file_size, o->read_times, o->cg_limit);
	printf("prot: %.3fs   victim: %.3fs\n", prot_t, victim_t);
	if (!o->no_baseline) {
		printf("prot  : baseline=%.3fs protected=%.3fs speedup=%+.1f%%\n",
		       base_prot, prot_t,
		       base_prot > 0.0 ? 100.0 * (base_prot - prot_t) / base_prot : 0.0);
		printf("victim: baseline=%.3fs protected=%.3fs change=%+.1f%%\n",
		       base_victim, victim_t,
		       base_victim > 0.0 ? 100.0 * (base_victim - victim_t) / base_victim : 0.0);
	}

	ret = 0;

out:
	/* Detach the policy before tearing anything down. */
	bpf_link__destroy(link);
	memcg_async_reclaim__destroy(skel);
	if (prot_fd >= 0)
		close(prot_fd);
	cleanup_cgroup_environment();

	return ret;
}

/* watch mode code */

static int do_watch(struct options *o)
{
	struct session s = {};
	__u64 monitor_id, target_id = 0;
	bool reclaim = o->control_mask & CTL_RECLAIM;
	char obs[32], ctl[32];
	double next_stats, deadline = 0;
	int ret = 1;

	/*
	 * Observing through the low/min hooks means counting them and reporting
	 * what they saw, which is not built yet. Reject it rather than accept a
	 * mask bit that does nothing: a counter stuck at 0 would then be
	 * indistinguishable from "the kernel never consulted the hook", which is
	 * a real failure mode that deserves to keep that meaning to itself.
	 */
	if (o->observe_mask & (OBS_LOW | OBS_MIN)) {
		fprintf(stderr, "ERROR: --observe low|min is not implemented yet; so far\n"
			"       watch can only observe refaults\n");
		return 1;
	}

	if (!o->monitor_path) {
		fprintf(stderr, "ERROR: watch needs --monitor\n");
		return 1;
	}
	if (reclaim && !o->target_path) {
		fprintf(stderr, "ERROR: --control reclaim needs --target\n");
		return 1;
	}

	if (resolve_memcg(o->monitor_path, &monitor_id))
		return 1;
	/* Without --control reclaim there is no engine and nothing to reclaim. */
	if (reclaim && resolve_memcg(o->target_path, &target_id))
		return 1;

	if (session_start(&s, o, monitor_id, target_id))
		return 1;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	fmt_methods(obs, sizeof(obs), o->observe_mask, observe_methods,
		    ARRAY_SIZE(observe_methods));
	fmt_methods(ctl, sizeof(ctl), o->control_mask, control_methods,
		    ARRAY_SIZE(control_methods));

	printf("monitor: %s (id %llu)\n", o->monitor_path,
	       (unsigned long long)monitor_id);
	if (reclaim)
		printf("target:  %s (id %llu)\n", o->target_path,
		       (unsigned long long)target_id);
	printf("observe=%s control=%s\n", obs, ctl);
	if (reclaim)
		printf("interval=%lums threshold=%lu batch=%lu max_batches=%lu swappiness=%ld\n",
		       o->interval_ms, o->threshold, o->batch_bytes, o->max_batches,
		       o->swappiness);
	if (o->duration_sec)
		printf("running for %lus, ", o->duration_sec);
	printf("interrupt with SIGINT to stop\n\n");

	next_stats = now_sec() + o->stats_sec;
	if (o->duration_sec)
		deadline = s.start + o->duration_sec;

	while (!READ_ONCE(exiting)) {
		double now = now_sec();
		int wait_ms;

		if (deadline && now >= deadline)
			break;

		wait_ms = (int)((next_stats - now) * 1000);
		if (wait_ms < 0)
			wait_ms = 0;

		if (session_poll(&s, wait_ms)) {
			fprintf(stderr, "ERROR: ring buffer poll failed\n");
			goto out;
		}

		if (now_sec() >= next_stats) {
			char prefix[32];

			snprintf(prefix, sizeof(prefix), "[%5.0fs]",
				 now_sec() - s.start);
			print_counters(&s, prefix);
			next_stats += o->stats_sec;
		}
	}

	ret = 0;

out:
	session_stop(&s);

	return ret;
}

/* cli code */

static void usage(const char *prog)
{
	printf("Usage: %s <mode> [options]\n\n"
	       "Modes:\n"
	       "  bench    create a high/low priority cgroup pair, run a memory\n"
	       "           pressured workload in both, and report the effect of\n"
	       "           asynchronous reclaim on the pressured one\n"
	       "  lowmin   like bench, but protect a cgroup with the memory.low/min\n"
	       "           BPF policy hooks instead of refault-driven reclaim\n"
	       "  watch    watch an existing cgroup and reclaim from another one\n"
	       "           whenever it comes under pressure, until interrupted;\n"
	       "           --control can protect the watched one instead\n\n"
	       "Common options:\n"
	       "  -i, --interval MS     monitor tick (bench: %d, watch: %d)\n"
	       "  -t, --threshold N     refault delta per tick that starts a round (%d)\n"
	       "  -b, --batch BYTES     bytes requested per callback (%luK)\n"
	       "  -n, --max-batches N   callbacks per reclaim round (%d)\n"
	       "  -S, --swappiness N    -1 = the memcg's own, 0..200, 201 = anon\n"
	       "                        pages only (needs swap; the default) (%ld)\n"
	       "  -v, --verbose         print every reclaim event\n"
	       "  -h, --help\n\n"
	       "bench options:\n"
	       "  -l, --limit BYTES     memory.max for the test cgroups (%luM)\n"
	       "  -f, --file-size BYTES workload file size (%luM)\n"
	       "  -R, --read-times N    workload re-read iterations (%lu)\n"
	       "      --no-baseline     skip the run without the BPF program\n\n"
	       "watch options:\n"
	       "  -m, --monitor PATH    cgroup to watch (required)\n"
	       "  -T, --target PATH     cgroup to reclaim from (needed by --control reclaim)\n"
	       "  -D, --duration SEC    stop after SEC seconds instead of on signal\n"
	       "  -s, --stats SEC       print a statistics line every SEC seconds (%d)\n"
	       "      --observe METHODS refault | low | min, ','-separated (refault);\n"
	       "                        low and min are not implemented yet\n"
	       "      --control METHODS reclaim | low | min, ','-separated (reclaim).\n"
	       "                        low/min answer BELOW from the monitor's\n"
	       "                        memory.low/min BPF hook, so reclaim skips it and\n"
	       "                        --target becomes optional. min is hard and can OOM\n"
	       "                        the target; low is soft and yields once nothing\n"
	       "                        else can be reclaimed. Both cover PATH itself,\n"
	       "                        not its children.\n\n"
	       "lowmin options (shares -l/-f/-R/--no-baseline with bench; -f defaults to\n"
	       "                a fraction of -l - 3/4 for min/both, 5/8 for low - so prot\n"
	       "                stays protected without OOMing victim):\n"
	       "  -L, --level LEVEL     low | min | both: which policy asserts BELOW (min)\n"
	       "      --events          also read prot's memory.events low count\n\n"
	       "BYTES accepts a K, M or G suffix. All modes need root.\n\n"
	       "One call to bpf_proactive_reclaim() reclaims at most the kernel's\n"
	       "MEMCG_CHARGE_BATCH pages, so --batch above that limit only means a\n"
	       "round needs more callbacks, not that a single callback does more.\n",
	       prog, BENCH_INTERVAL_MS, WATCH_INTERVAL_MS, DEFAULT_THRESHOLD,
	       DEFAULT_BATCH_BYTES / 1024, DEFAULT_MAX_BATCHES,
	       DEFAULT_SWAPPINESS, DEFAULT_CG_LIMIT / (1024 * 1024),
	       DEFAULT_FILE_SIZE / (1024 * 1024), DEFAULT_READ_TIMES,
	       DEFAULT_STATS_SEC);
}

enum {
	OPT_NO_BASELINE = 256,
	OPT_EVENTS,
	OPT_OBSERVE,
	OPT_CONTROL,
};

static int parse_options(int argc, char **argv, struct options *o)
{
	static const struct option long_opts[] = {
		{ "interval",	required_argument,	NULL, 'i' },
		{ "threshold",	required_argument,	NULL, 't' },
		{ "batch",	required_argument,	NULL, 'b' },
		{ "max-batches",	required_argument,	NULL, 'n' },
		{ "swappiness",	required_argument,	NULL, 'S' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "limit",	required_argument,	NULL, 'l' },
		{ "file-size",	required_argument,	NULL, 'f' },
		{ "read-times",	required_argument,	NULL, 'R' },
		{ "no-baseline",	no_argument,		NULL, OPT_NO_BASELINE },
		{ "monitor",	required_argument,	NULL, 'm' },
		{ "target",	required_argument,	NULL, 'T' },
		{ "duration",	required_argument,	NULL, 'D' },
		{ "stats",	required_argument,	NULL, 's' },
		{ "level",	required_argument,	NULL, 'L' },
		{ "events",	no_argument,		NULL, OPT_EVENTS },
		{ "observe",	required_argument,	NULL, OPT_OBSERVE },
		{ "control",	required_argument,	NULL, OPT_CONTROL },
		{ }
	};
	int c;

	while ((c = getopt_long(argc, argv, "i:t:b:n:S:vhl:f:R:m:T:D:s:L:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			if (parse_ulong(optarg, &o->interval_ms))
				return -1;
			break;
		case 't':
			if (parse_ulong(optarg, &o->threshold))
				return -1;
			break;
		case 'b':
			if (parse_size(optarg, &o->batch_bytes))
				return -1;
			break;
		case 'n':
			if (parse_ulong(optarg, &o->max_batches))
				return -1;
			break;
		case 'S':
			if (parse_long(optarg, &o->swappiness))
				return -1;
			break;
		case 'v':
			o->verbose = true;
			break;
		case 'l':
			if (parse_size(optarg, &o->cg_limit))
				return -1;
			break;
		case 'f':
			if (parse_size(optarg, &o->file_size))
				return -1;
			break;
		case 'R':
			if (parse_ulong(optarg, &o->read_times))
				return -1;
			break;
		case OPT_NO_BASELINE:
			o->no_baseline = true;
			break;
		case 'm':
			o->monitor_path = optarg;
			break;
		case 'T':
			o->target_path = optarg;
			break;
		case 'D':
			if (parse_ulong(optarg, &o->duration_sec))
				return -1;
			break;
		case 's':
			if (parse_ulong(optarg, &o->stats_sec))
				return -1;
			break;
		case 'L':
			o->level_given = true;
			if (!strcmp(optarg, "low"))
				o->prot_level = LEVEL_LOW;
			else if (!strcmp(optarg, "min"))
				o->prot_level = LEVEL_MIN;
			else if (!strcmp(optarg, "both"))
				o->prot_level = LEVEL_BOTH;
			else {
				fprintf(stderr, "ERROR: --level must be low, min or both\n");
				return -1;
			}
			break;
		case OPT_EVENTS:
			o->events = true;
			break;
		case OPT_OBSERVE:
			if (parse_methods(optarg, &o->observe_mask,
					  observe_methods,
					  ARRAY_SIZE(observe_methods),
					  "--observe"))
				return -1;
			break;
		case OPT_CONTROL:
			if (parse_methods(optarg, &o->control_mask,
					  control_methods,
					  ARRAY_SIZE(control_methods),
					  "--control"))
				return -1;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct options o = {
		.threshold = DEFAULT_THRESHOLD,
		.batch_bytes = DEFAULT_BATCH_BYTES,
		.max_batches = DEFAULT_MAX_BATCHES,
		.swappiness = DEFAULT_SWAPPINESS,
		.cg_limit = DEFAULT_CG_LIMIT,
		/* file_size stays 0 here; defaulted per mode below (bench/lowmin differ) */
		.read_times = DEFAULT_READ_TIMES,
		.stats_sec = DEFAULT_STATS_SEC,
		/* observe_mask/control_mask stay 0; defaulted after parsing */
		.prot_level = LEVEL_MIN,
	};
	const char *mode;
	bool bench, lowmin, watch;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	mode = argv[1];
	if (!strcmp(mode, "-h") || !strcmp(mode, "--help")) {
		usage(argv[0]);
		return 0;
	}

	bench = !strcmp(mode, "bench");
	lowmin = !strcmp(mode, "lowmin");
	if (!bench && !lowmin && strcmp(mode, "watch")) {
		fprintf(stderr, "ERROR: unknown mode '%s', expected bench, lowmin or watch\n\n",
			mode);
		usage(argv[0]);
		return 1;
	}
	watch = !bench && !lowmin;	/* an unknown mode has already returned */

	/* Let getopt_long see the options rather than the mode. */
	optind = 2;
	if (parse_options(argc, argv, &o)) {
		usage(argv[0]);
		return 1;
	}

	/* Applied here, not in the initializer: see parse_methods(). */
	if (!o.observe_mask)
		o.observe_mask = OBS_REFAULT;
	if (!o.control_mask)
		o.control_mask = CTL_RECLAIM;

	/*
	 * The selectors mean something only to watch and --level only to lowmin.
	 * Silently ignoring them in the wrong mode would look exactly like the
	 * option having no effect. Comparing against the defaults is enough: any
	 * other value can only have come from the command line.
	 */
	if (!watch && (o.observe_mask != OBS_REFAULT ||
		       o.control_mask != CTL_RECLAIM)) {
		fprintf(stderr, "ERROR: --observe/--control are watch options\n");
		return 1;
	}
	if (!lowmin && o.level_given) {
		fprintf(stderr, "ERROR: --level is a lowmin-mode option (watch uses --control low|min)\n");
		return 1;
	}

	if (!o.interval_ms)
		o.interval_ms = bench ? BENCH_INTERVAL_MS : WATCH_INTERVAL_MS;
	if (!o.file_size) {
		/*
		 * lowmin sizes the fill from the parent limit so the demo is
		 * clean and OOM-free; see do_lowmin(). low is soft and cannot
		 * OOM, so it uses gentler pressure (5/8) that victim absorbs
		 * without prot being breached. min/both are hard, so prot's fill
		 * must stay below the limit (3/4) or victim OOMs.
		 */
		if (!lowmin)
			o.file_size = DEFAULT_FILE_SIZE;
		else if (o.prot_level == LEVEL_LOW)
			o.file_size = o.cg_limit / 8 * 5;
		else
			o.file_size = o.cg_limit / 4 * 3;
	}
	if (!o.stats_sec)
		o.stats_sec = DEFAULT_STATS_SEC;
	if (!o.threshold || !o.batch_bytes || !o.max_batches) {
		fprintf(stderr, "ERROR: --threshold, --batch and --max-batches must be non-zero\n");
		return 1;
	}
	if (o.swappiness != -1 && (o.swappiness < 0 || o.swappiness > 201)) {
		fprintf(stderr, "ERROR: --swappiness must be -1, 0..200, or 201\n");
		return 1;
	}
	/*
	 * One round budgets max_batches * batch_bytes, and the BPF side keeps
	 * requeueing until it is spent, so bound the product: it also keeps the
	 * multiplication from wrapping.
	 */
	if (o.max_batches > (1UL << 30) / o.batch_bytes) {
		fprintf(stderr, "ERROR: --max-batches * --batch must not exceed 1G\n");
		return 1;
	}

	if (bench)
		return do_bench(&o);
	if (lowmin)
		return do_lowmin(&o);
	return do_watch(&o);
}
