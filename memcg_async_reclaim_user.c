// SPDX-License-Identifier: GPL-2.0
/*
 * memcg_async_reclaim - refault-driven asynchronous proactive reclaim
 *
 * A BPF program watches the workingset refaults of one cgroup and, whenever
 * they grow, reclaims from a second cgroup on a workqueue through
 * bpf_proactive_reclaim(). The monitored workload is never blocked: reclaim
 * runs asynchronously, in bounded batches, against somebody else's memory.
 *
 * Two modes:
 *
 *   bench  Create a high/low priority cgroup pair, run a memory-pressured
 *          workload in both, and report the effect on the pressured one. By
 *          default the same workload is first run without the BPF program to
 *          produce a baseline. Self-contained: creates and removes everything.
 *
 *   watch  Watch two existing cgroups given by path and keep reclaiming for as
 *          long as the program runs. Removing the target while it runs is
 *          handled: reclaim stops and the events say so.
 *
 * Both modes need root.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
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
#include "policy.h"
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

/* How long a single ring_buffer__poll() blocks while waiting for a signal. */
#define POLL_SLICE_MS		200

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
	/* cmp */
	const char *impl_str;
	const char *trigger_str;
	const char *csv_path;
	unsigned long psi_us;
	unsigned long hysteresis_ms;
	unsigned long read_cycle_ms;
	unsigned long filler_sleep_ms;
	unsigned long budget;
	unsigned long tmax;
	unsigned long filler_bytes;
	unsigned long burst_bytes;
	unsigned long ramp_sec;
	unsigned long agent_min;
};

struct counters {
	unsigned long long rounds;
	unsigned long long calls;
	unsigned long long bytes;
};

struct session {
	struct memcg_async_reclaim *skel;
	struct ring_buffer *rb;
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
	int init_fd, err;

	s->verbose = o->verbose;
	s->start = now_sec();

	s->skel = memcg_async_reclaim__open_and_load();
	if (!s->skel) {
		fprintf(stderr, "ERROR: failed to open or load the BPF object\n");
		return -1;
	}

	/*
	 * The syscall program installs the timer and the work item into the
	 * map and starts the timer; from then on the chain runs on its own.
	 */
	init_fd = bpf_program__fd(s->skel->progs.reclaim_prog_init);
	err = bpf_prog_test_run_opts(init_fd, &run_opts);
	if (err || run_opts.retval) {
		fprintf(stderr, "ERROR: reclaim_prog_init failed: %s (retval %d)\n",
			err ? strerror(errno) : "rejected by the program",
			run_opts.retval);
		goto err_out;
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
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;

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

	printf("%s rounds=%llu(+%llu) calls=%llu(+%llu) reclaimed=%s(+%s)\n",
	       prefix, now.rounds, now.rounds - s->last.rounds,
	       now.calls, now.calls - s->last.calls, bytes, delta);

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
	printf("events: called=%llu skipped_dying=%llu target_gone=%llu\n",
	       s->called, s->skipped_dying, s->target_gone);
	if (failures)
		printf("WARNING: monitor timer rearm failed %llu time(s), reclaim stopped early\n",
		       failures);
	if (last_err)
		printf("WARNING: bpf_proactive_reclaim() last failed with -%llu\n",
		       last_err);

	/* Destroying the skeleton drops the map, which cancels timer and wq. */
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;
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
	CHILD_EXIT_OPEN_FILES,
	CHILD_EXIT_PSI_OPEN,
	CHILD_EXIT_PSI_TRIGGER,
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
	case CHILD_EXIT_OPEN_FILES:
		return "open memory.current/memory.low";
	case CHILD_EXIT_PSI_OPEN:
		return "open memory.pressure";
	case CHILD_EXIT_PSI_TRIGGER:
		return "arm PSI trigger";
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
		if (WEXITSTATUS(status) == CHILD_EXIT_PSI_OPEN ||
		    WEXITSTATUS(status) == CHILD_EXIT_PSI_TRIGGER)
			fprintf(stderr, "       PSI unavailable? boot with psi=1\n");
		return -1;
	}

	return 0;
}

/*
 * Run the workload in the high and low priority cgroups at the same time and
 * report how long each took. The high priority one is the cgroup the BPF
 * program protects, the low priority one is what it reclaims from.
 */
static int run_workload(const char *dir, const struct options *o,
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
		_exit(child_work(BENCH_CG_LOW_DIR, low_data_fd, low_time_fd, o));

	high_pid = fork();
	if (high_pid < 0) {
		fprintf(stderr, "ERROR: fork high: %s\n", strerror(errno));
		goto cleanup;
	}
	if (high_pid == 0)
		_exit(child_work(BENCH_CG_HIGH_DIR, high_data_fd, high_time_fd, o));

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
		if (run_workload(dir, o, &base_high, &base_low))
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
	if (run_workload(dir, o, &high, &low))
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

/* watch mode code */

static int do_watch(struct options *o)
{
	struct session s = {};
	__u64 monitor_id, target_id;
	double next_stats, deadline = 0;
	int ret = 1;

	if (!o->monitor_path || !o->target_path) {
		fprintf(stderr, "ERROR: watch needs both --monitor and --target\n");
		return 1;
	}

	monitor_id = cgroup_id_from_path(o->monitor_path);
	if (!monitor_id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", o->monitor_path,
			strerror(errno));
		return 1;
	}
	if (!memcg_on_path(o->monitor_path)) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory\n"
			"       controller is not enabled on that cgroup.\n",
			o->monitor_path);
		return 1;
	}

	target_id = cgroup_id_from_path(o->target_path);
	if (!target_id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", o->target_path,
			strerror(errno));
		return 1;
	}
	if (!memcg_on_path(o->target_path)) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory\n"
			"       controller is not enabled on that cgroup.\n",
			o->target_path);
		return 1;
	}

	if (session_start(&s, o, monitor_id, target_id))
		return 1;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	printf("monitor: %s (id %llu)\n", o->monitor_path,
	       (unsigned long long)monitor_id);
	printf("target:  %s (id %llu)\n", o->target_path,
	       (unsigned long long)target_id);
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

/* ===================== cmp: three-arm comparison ===================== */

/*
 * Topology. setup_cgroup_environment() mounts a private cgroup2 view at
 * /mnt (this mirrors CGROUP_MOUNT_PATH in cgroup_helpers.c) and enables all
 * controllers at its root. The budget cgroup T is placed as a direct child
 * of that root: the helpers' workdir-relative paths would interpose a
 * cgroup with memory.low == 0 between T and the root, which caps every
 * request to 0 under global reclaim. The workload pressure here comes from
 * T's own memory.max, so the reclaim it triggers is rooted at T, and A - a
 * direct child of T - rides the uncapped parent == root fast path of
 * page_counter_calculate_protection(); T's memory.low shields the subtree
 * against system-wide reclaim.
 *
 *   /mnt                       cgroup2 root, all controllers enabled
 *   +-- memcg_cmp_t        T: memory.max = --tmax, memory.low = --budget,
 *                            memory.swap.max = 0
 *       |-- a              A: paced re-reader, the protected one
 *       |-- b              B: continuous rewriter, a renewable cold-page flow
 *       |-- c              C: one-shot anon ballast, unreclaimable (swap off)
 *       +-- agent          the U arm's child, memory.min = --agent-min
 *
 * The pressure model is a flow, not a stock. B's rewrite loop keeps charging
 * pages against T's max, so reclaim keeps running for the whole window and
 * keeps eating the coldest supply - mostly B's own tail, but the proportional
 * scan visits A as well and evicts whatever A has not referenced since its
 * last paced pass. Those evictions land in A's pgsteal count: the evidence
 * all three arms trigger on. (Workingset refaults, the textbook signal, are
 * blind here: they need the shadow entry the eviction left behind, and the
 * shadow_nodes shrinker - which runs inside every one of B's reclaim passes -
 * wipes it long before A's paced re-read. See the BPF side.) Under
 * protection A is skipped entirely and its pgsteal stops growing. C's anon
 * ballast shrinks the file pool to (tmax - burst),
 * raising A's share of the scan; as long as A's full working set plus the
 * ballast fit under --tmax, the protection floor is met and reclaim never
 * has to override a request. Two knobs keep the arms distinguishable:
 * --read-cycle paces A (a tight loop keeps every page referenced hundreds
 * of times a second and wins any LRU competition outright) and B's loop
 * renews the fodder (a one-shot filler is eaten once, after which the only
 * supply left is A - protected or not). --filler must keep A + B under
 * --tmax: the ramp then has headroom, no reclaim runs, and the arms stay
 * silent until the burst pushes T over its max - first protection is
 * measured against the burst, not against ramp-time dribble.
 *
 * The agent's memory.min is disclosed: the userspace arm's action path has
 * to survive the very pressure it is reacting to. It does not close the
 * window being measured - the agent still only acts between passes.
 */
#define CMP_MOUNT_PATH		"/mnt"
#define CMP_T_DIR		CMP_MOUNT_PATH "/memcg_cmp_t"
#define CMP_A_DIR		CMP_T_DIR "/a"
#define CMP_B_DIR		CMP_T_DIR "/b"
#define CMP_C_DIR		CMP_T_DIR "/c"
#define CMP_AGENT_DIR		CMP_T_DIR "/agent"

#define DEFAULT_CMP_INTERVAL_MS		5
#define DEFAULT_CMP_DURATION_SEC	30
#define DEFAULT_CMP_RAMP_SEC		5
#define DEFAULT_CMP_RATE		12800UL	/* A usage-drop pages per second */
#define DEFAULT_CMP_READ_CYCLE_MS	500
#define DEFAULT_CMP_FILLER_SLEEP_MS	500
#define DEFAULT_CMP_HYSTERESIS_MS	50
#define DEFAULT_CMP_BUDGET		(64UL * 1024 * 1024)
#define DEFAULT_CMP_TMAX		(160UL * 1024 * 1024)
/* A_full + B_full must stay under --tmax, or the ramp already runs reclaim
 * and the arms latch protection before the burst they are meant to react to.
 */
#define DEFAULT_CMP_FILLER		(112UL * 1024 * 1024)
#define DEFAULT_CMP_AGENT_MIN		(8UL * 1024 * 1024)
#define DEFAULT_CMP_PSI_US		10000

/* The poll trigger's window: stall microseconds per 1s of wall time. */
#define CMP_PSI_WINDOW_US		1000000

enum cmp_impl {
	CMP_IMPL_USER,
	CMP_IMPL_BPF_POLL,
	CMP_IMPL_BPF_HOOK,
	CMP_IMPL_SANITY,
};

enum cmp_trigger {
	CMP_TRIG_TIMER,
	CMP_TRIG_POLL,
};

/* Written by the A reader child on SIGTERM; read back by the parent. */
struct cmp_child_report {
	__u64 iters;
	__u64 sum_ns;
	__u64 max_ns;
};

/* Written by the U arm's agent child on SIGTERM. Timestamps are
 * CLOCK_MONOTONIC, the same clock bpf_ktime_get_ns() uses, so the agent's
 * first_protect_ns is directly comparable with cmp_first_request_ns.
 */
struct cmp_agent_report {
	__u64 decisions;
	__u64 writes;
	__u64 first_protect_ns;
	__u64 sample_sum_ns;
	__u64 sample_max_ns;
};

struct cmp_snapshot {
	unsigned long long steal_a;
	unsigned long long refault_a;
	unsigned long long low_events_a;
	unsigned long long psi_a_us;
	unsigned long long psi_b_us;
	unsigned long long cur_a, cur_b, cur_c, cur_t;
	unsigned long long cpu_a_us, cpu_b_us, cpu_c_us, cpu_agent_us;
};

static volatile sig_atomic_t cmp_child_stop;

static void cmp_child_handle_term(__maybe_unused int sig)
{
	cmp_child_stop = 1;
}

static __u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

/*
 * Absolute-path cgroup helpers: the cgroup_helpers.c API prepends the
 * per-process workdir, and cmp's T has to sit at the root of the mount.
 */

static int cmp_write_str(const char *dir, const char *file, const char *val)
{
	char path[PATH_MAX];
	int fd, ret = -1;

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	/*
	 * O_WRONLY: write-only files like /proc/sys/vm/drop_caches reject
	 * O_RDWR even for root (CAP_DAC_OVERRIDE grants no read when no read
	 * bit is set at all).
	 */
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		log_err("opening %s", path);
		return -1;
	}
	if (write(fd, val, strlen(val)) >= 0)
		ret = 0;
	else
		log_err("writing '%s' to %s", val, path);
	close(fd);

	return ret;
}

static int cmp_write_ull(const char *dir, const char *file,
			 unsigned long long val)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "%llu", val);

	return cmp_write_str(dir, file, buf);
}

static int cmp_read_file(const char *dir, const char *file, char *buf,
			 size_t len)
{
	char path[PATH_MAX];
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = pread(fd, buf, len - 1, 0);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';

	return (int)n;
}

static unsigned long long cmp_read_ull(const char *dir, const char *file)
{
	char buf[64];

	if (cmp_read_file(dir, file, buf, sizeof(buf)) < 0)
		return 0;

	return strtoull(buf, NULL, 10);
}

/* Matches "key VALUE" at the start of a line; a missing key reads as 0. */
static unsigned long long cmp_parse_key(const char *buf, const char *key)
{
	size_t klen = strlen(key);
	const char *p = buf;

	while (p && *p) {
		if (!strncmp(p, key, klen) && p[klen] == ' ')
			return strtoull(p + klen + 1, NULL, 10);
		p = strchr(p, '\n');
		if (p)
			p++;
	}

	return 0;
}

static unsigned long long cmp_events_low(const char *dir)
{
	char buf[256];

	if (cmp_read_file(dir, "memory.events", buf, sizeof(buf)) < 0)
		return 0;

	return cmp_parse_key(buf, "low");
}

static unsigned long long cmp_psi_some_us(const char *dir)
{
	char buf[512];
	char *p;

	if (cmp_read_file(dir, "memory.pressure", buf, sizeof(buf)) < 0)
		return 0;
	p = strstr(buf, "some ");
	if (!p)
		return 0;
	p = strstr(p, "total=");
	if (!p)
		return 0;

	return strtoull(p + 6, NULL, 10);
}

static unsigned long long cmp_refaults(const char *dir)
{
	char buf[8192];

	if (cmp_read_file(dir, "memory.stat", buf, sizeof(buf)) < 0)
		return 0;

	return cmp_parse_key(buf, "workingset_refault_anon") +
	       cmp_parse_key(buf, "workingset_refault_file");
}

/* A's "pgsteal": pages reclaim stole from A - the cmp arms' evidence. The
 * BPF side sums the same four counters the kernel aggregates into this line.
 */
static unsigned long long cmp_steals(const char *dir)
{
	char buf[8192];

	if (cmp_read_file(dir, "memory.stat", buf, sizeof(buf)) < 0)
		return 0;

	return cmp_parse_key(buf, "pgsteal");
}

static unsigned long long cmp_cpu_usage_us(const char *dir)
{
	char buf[256];

	if (cmp_read_file(dir, "cpu.stat", buf, sizeof(buf)) < 0)
		return 0;

	return cmp_parse_key(buf, "usage_usec");
}

static int cmp_join(const char *dir)
{
	char path[PATH_MAX];
	int fd, ret = -1;

	snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		log_err("opening %s", path);
		return -1;
	}
	if (dprintf(fd, "%d", getpid()) > 0)
		ret = 0;
	else
		log_err("joining %s", dir);
	close(fd);

	return ret;
}

static int cmp_read_report(int fd, void *out, size_t sz)
{
	if (fd < 0 || lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return -1;
	if (read(fd, out, sz) != (ssize_t)sz)
		return -1;

	return 0;
}

/* Workload children. Each installs its own SIGTERM handler: the parent's
 * handler is inherited across fork and watches a flag only the parent's
 * loops read. SIGINT is ignored so that a terminal Ctrl-C reaches the
 * children only through the parent's orderly kill.
 */

static int cmp_child_reader(const char *cg_dir, int data_fd, int report_fd,
			    unsigned long file_size, unsigned long cycle_ms)
{
	struct cmp_child_report rep = {};

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, cmp_child_handle_term);

	if (cmp_join(cg_dir))
		return CHILD_EXIT_JOIN_CGROUP;
	if (write_file(data_fd, file_size))
		return CHILD_EXIT_WRITE_FILE;

	while (!cmp_child_stop) {
		__u64 t0 = mono_ns(), d;

		if (read_file(data_fd, file_size, 1))
			return CHILD_EXIT_READ_FILE;
		d = mono_ns() - t0;
		rep.iters++;
		rep.sum_ns += d;
		if (d > rep.max_ns)
			rep.max_ns = d;

		/*
		 * Pace the passes to one reference per page per cycle. A
		 * tight loop keeps every page referenced hundreds of times a
		 * second, wins any LRU competition outright and hides what
		 * protection buys; a paced reader is the workload the
		 * comparison is about. Reported latencies exclude the pause.
		 */
		if (cycle_ms && d < (__u64)cycle_ms * 1000000ULL)
			usleep((useconds_t)(((__u64)cycle_ms * 1000000ULL - d)
					    / 1000));
	}

	if (write(report_fd, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
		return CHILD_EXIT_TIME_FILE;

	return CHILD_EXIT_OK;
}

static int cmp_child_filler(const char *cg_dir, int data_fd,
			    unsigned long filler_bytes, unsigned long sleep_ms)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, cmp_child_handle_term);

	if (cmp_join(cg_dir))
		return CHILD_EXIT_JOIN_CGROUP;

	/*
	 * Rewrite the file in a loop. A one-shot filler is a finite stock of
	 * cold pages: once reclaim has eaten it, the only supply left is A,
	 * protected or not. A continuous writer is a renewable flow: its own
	 * tail is always the coldest memory in T, so reclaim keeps a steady
	 * supply of unprotected victims for the whole window. Staying alive
	 * also keeps B's css online, so its cache stays reclaimable.
	 */
	while (!cmp_child_stop) {
		if (lseek(data_fd, 0, SEEK_SET) < 0)
			return CHILD_EXIT_WRITE_FILE;
		if (write_file(data_fd, filler_bytes))
			return CHILD_EXIT_WRITE_FILE;
		if (sleep_ms)
			usleep((useconds_t)sleep_ms * 1000);
	}

	return CHILD_EXIT_OK;
}

static int cmp_child_burst(const char *cg_dir, unsigned long burst_bytes)
{
	char *p;

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, cmp_child_handle_term);

	if (cmp_join(cg_dir))
		return CHILD_EXIT_JOIN_CGROUP;

	p = mmap(NULL, burst_bytes, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return CHILD_EXIT_WRITE_FILE;
	memset(p, 0xa5, burst_bytes);

	while (!cmp_child_stop)
		pause();

	return CHILD_EXIT_OK;
}

/* The U arm. Same policy.h arithmetic as the B arms, on the same counter
 * (A's memory.current - the live page_counter, no stats flush involved),
 * with the actions a userspace agent has: wake on a PSI trigger or a timer,
 * pread memory.current, write memory.low. The sample doubles as the action:
 * while protecting, every tick writes the memory.current it just read to
 * memory.low, matching the kernel-side REQUEST_USAGE semantics of "protect
 * my whole usage" re-evaluated on every pass - the snapshot's staleness and
 * the rewrite's cost are part of what the arm measures.
 */
struct cmp_agent_cfg {
	int use_poll;
	unsigned long interval_ms;
	unsigned long psi_us;
	unsigned long page_size;
	__u64 rate;
	__u64 hysteresis_ns;
};

/* Reads A's memory.current into @buf (kept as bytes text for the memory.low
 * write) and converts it to pages for the policy. */
static int cmp_agent_read_usage(int cur_fd, char *buf, size_t len,
				unsigned long page_size, __u64 *pages)
{
	ssize_t n = pread(cur_fd, buf, len - 1, 0);

	if (n <= 0)
		return -1;
	buf[n] = '\0';
	*pages = strtoull(buf, NULL, 10) / page_size;

	return 0;
}

static int cmp_child_agent(const struct cmp_agent_cfg *ac, int report_fd)
{
	struct cmp_agent_report rep = {};
	struct policy_state st = {};
	char curbuf[64], trig[64];
	int cur_fd, low_fd, psi_fd = -1;
	int last = -1;

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, cmp_child_handle_term);

	if (cmp_join(CMP_AGENT_DIR))
		return CHILD_EXIT_JOIN_CGROUP;

	cur_fd = open(CMP_A_DIR "/memory.current", O_RDONLY);
	low_fd = open(CMP_A_DIR "/memory.low", O_RDWR);
	if (cur_fd < 0 || low_fd < 0)
		return CHILD_EXIT_OPEN_FILES;

	if (ac->use_poll) {
		psi_fd = open(CMP_A_DIR "/memory.pressure", O_RDWR);
		if (psi_fd < 0)
			return CHILD_EXIT_PSI_OPEN;
		snprintf(trig, sizeof(trig), "some %lu %d", ac->psi_us,
			 CMP_PSI_WINDOW_US);
		if (write(psi_fd, trig, strlen(trig)) < 0)
			return CHILD_EXIT_PSI_TRIGGER;
	}

	/* A failed seed leaves prev_level at 0, which the fall-based policy
	 * turns into "first sample carries no evidence", never a false one.
	 */
	cmp_agent_read_usage(cur_fd, curbuf, sizeof(curbuf), ac->page_size,
			     &st.prev_level);
	st.prev_ns = mono_ns();

	while (!cmp_child_stop) {
		__u64 t0, t1, level;
		int protect;

		if (ac->use_poll) {
			struct pollfd pfd = {
				.fd	= psi_fd,
				.events	= POLLPRI | POLLERR,
			};
			int n = poll(&pfd, 1, -1);

			/* EINTR means SIGTERM set the stop flag. */
			if (n <= 0)
				break;
			/* PSI triggers are one-shot; re-arm before sampling. */
			if (pwrite(psi_fd, trig, strlen(trig), 0) < 0)
				break;
		} else {
			struct timespec ts = {
				.tv_sec		= (time_t)(ac->interval_ms / 1000),
				.tv_nsec	= (long)(ac->interval_ms % 1000) * 1000000L,
			};

			clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
		}
		if (cmp_child_stop)
			break;

		t0 = mono_ns();
		if (cmp_agent_read_usage(cur_fd, curbuf, sizeof(curbuf),
					 ac->page_size, &level))
			break;
		protect = policy_protect(&st, level, t0, ac->rate,
					 ac->hysteresis_ns);
		if (protect) {
			/*
			 * The sample doubles as the protection snapshot: the
			 * kernel-side REQUEST_USAGE re-reads usage on every
			 * pass, so a write-once memory.low would freeze the
			 * protection at whatever A held when it first
			 * triggered and cap A below its real working set.
			 */
			if (pwrite(low_fd, curbuf, strlen(curbuf), 0) < 0)
				break;
			rep.writes++;
			t1 = mono_ns();
			if (!rep.first_protect_ns)
				rep.first_protect_ns = t1;
		} else {
			if (last == 1 && pwrite(low_fd, "0", 1, 0) < 0)
				break;
			if (last == 1)
				rep.writes++;
			t1 = mono_ns();
		}
		last = protect;
		rep.decisions++;
		rep.sample_sum_ns += t1 - t0;
		if (t1 - t0 > rep.sample_max_ns)
			rep.sample_max_ns = t1 - t0;
	}

	/* Never leave protection behind for the next arm's round. */
	if (pwrite(low_fd, "0", 1, 0) < 0)
		fprintf(stderr, "WARNING: agent failed to reset memory.low\n");
	if (write(report_fd, &rep, sizeof(rep)) != (ssize_t)sizeof(rep))
		fprintf(stderr, "WARNING: agent failed to write its report\n");

	return CHILD_EXIT_OK;
}

/* Topology setup and teardown */

static int cmp_setup_topology(const struct options *o)
{
	static const char * const dirs[] = {
		CMP_A_DIR, CMP_B_DIR, CMP_C_DIR, CMP_AGENT_DIR
	};
	char buf[64];
	int i;

	if (setup_cgroup_environment())
		return -1;

	if (mkdir(CMP_T_DIR, 0777) && errno != EEXIST) {
		log_err("mkdir %s", CMP_T_DIR);
		return -1;
	}
	if (cmp_write_ull(CMP_T_DIR, "memory.max", o->tmax) ||
	    cmp_write_ull(CMP_T_DIR, "memory.low", o->budget))
		return -1;
	/*
	 * Swap off keeps C's anon unreclaimable, so sustained pressure has
	 * to come out of file cache and protection has a visible effect.
	 * Best effort: the file only exists with CONFIG_SWAP.
	 */
	if (!access("/proc/swaps", F_OK))
		cmp_write_str(CMP_T_DIR, "memory.swap.max", "0");

	/* Before the children exist: an internal process would make the
	 * subtree_control write fail.
	 */
	if (cmp_write_str(CMP_T_DIR, "cgroup.subtree_control", "+memory"))
		return -1;

	for (i = 0; i < (int)ARRAY_SIZE(dirs); i++)
		if (mkdir(dirs[i], 0777) && errno != EEXIST) {
			log_err("mkdir %s", dirs[i]);
			return -1;
		}

	if (o->agent_min &&
	    cmp_write_ull(CMP_AGENT_DIR, "memory.min", o->agent_min))
		return -1;

	if (cmp_read_file(CMP_T_DIR, "memory.current", buf, sizeof(buf)) < 0) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory controller\n"
			"       is not enabled at the root of the cgroup2 hierarchy.\n",
			CMP_T_DIR);
		return -1;
	}

	return 0;
}

static int cmp_rmdir_abs(const char *path)
{
	if (!rmdir(path) || errno == ENOENT)
		return 0;

	return -1;
}

static void cmp_teardown_cgroups(void)
{
	int i;

	/*
	 * The children's css pins their cgroups until their page cache is
	 * gone; dropping caches after the reaps makes the rmdirs succeed
	 * within a few retries. Best effort: the mount view dies with the
	 * process, but the cgroups belong to the real hierarchy.
	 */
	cmp_write_str("/proc/sys/vm", "drop_caches", "3");

	for (i = 0; i < 20; i++) {
		int ok = !cmp_rmdir_abs(CMP_A_DIR);

		ok &= !cmp_rmdir_abs(CMP_B_DIR);
		ok &= !cmp_rmdir_abs(CMP_C_DIR);
		ok &= !cmp_rmdir_abs(CMP_AGENT_DIR);
		if (ok && !cmp_rmdir_abs(CMP_T_DIR))
			break;
		usleep(100000);
	}

	cleanup_cgroup_environment();
}

/* Measurement helpers */

static void cmp_take_snapshot(struct cmp_snapshot *s)
{
	memset(s, 0, sizeof(*s));

	s->steal_a = cmp_steals(CMP_A_DIR);
	s->refault_a = cmp_refaults(CMP_A_DIR);
	s->low_events_a = cmp_events_low(CMP_A_DIR);
	s->psi_a_us = cmp_psi_some_us(CMP_A_DIR);
	s->psi_b_us = cmp_psi_some_us(CMP_B_DIR);
	s->cur_a = cmp_read_ull(CMP_A_DIR, "memory.current");
	s->cur_b = cmp_read_ull(CMP_B_DIR, "memory.current");
	s->cur_c = cmp_read_ull(CMP_C_DIR, "memory.current");
	s->cur_t = cmp_read_ull(CMP_T_DIR, "memory.current");
	s->cpu_a_us = cmp_cpu_usage_us(CMP_A_DIR);
	s->cpu_b_us = cmp_cpu_usage_us(CMP_B_DIR);
	s->cpu_c_us = cmp_cpu_usage_us(CMP_C_DIR);
	s->cpu_agent_us = cmp_cpu_usage_us(CMP_AGENT_DIR);
}

static int cmp_prog_run_info(struct bpf_program *prog, __u64 *run_time_ns,
			     __u64 *run_cnt)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	int fd;

	*run_time_ns = 0;
	*run_cnt = 0;

	fd = bpf_program__fd(prog);
	if (fd < 0 || bpf_obj_get_info_by_fd(fd, &info, &len))
		return -1;

	*run_time_ns = info.run_time_ns;
	*run_cnt = info.run_cnt;

	return 0;
}

static void cmp_set_bpf_stats(int on, int *prev)
{
	char buf[16];

	if (prev) {
		*prev = -1;
		if (cmp_read_file("/proc/sys/kernel", "bpf_stats_enabled",
				  buf, sizeof(buf)) >= 0)
			*prev = atoi(buf);
	}
	if (cmp_write_str("/proc/sys/kernel", "bpf_stats_enabled",
			  on ? "1" : "0"))
		fprintf(stderr, "WARNING: cannot set kernel.bpf_stats_enabled;"
			" BPF run_time stays 0\n");
}

static int cmp_parse_impl(const char *s, enum cmp_impl *out)
{
	if (!strcmp(s, "user"))
		*out = CMP_IMPL_USER;
	else if (!strcmp(s, "bpf-poll"))
		*out = CMP_IMPL_BPF_POLL;
	else if (!strcmp(s, "bpf-hook"))
		*out = CMP_IMPL_BPF_HOOK;
	else if (!strcmp(s, "sanity"))
		*out = CMP_IMPL_SANITY;
	else
		return -1;

	return 0;
}

static int cmp_parse_trigger(const char *s, enum cmp_trigger *out)
{
	if (!strcmp(s, "timer"))
		*out = CMP_TRIG_TIMER;
	else if (!strcmp(s, "poll"))
		*out = CMP_TRIG_POLL;
	else
		return -1;

	return 0;
}

static const char *cmp_trigger_str(enum cmp_trigger t)
{
	return t == CMP_TRIG_POLL ? "poll" : "timer";
}

static int do_cmp(struct options *o)
{
	char a_data[PATH_MAX], b_data[PATH_MAX], a_rep[PATH_MAX], g_rep[PATH_MAX];
	int a_data_fd = -1, b_data_fd = -1, a_rep_fd = -1, g_rep_fd = -1;
	int a_dir_fd = -1, init_fd, stats_prev = -1, ret = 1, valid;
	pid_t a_pid = -1, b_pid = -1, c_pid = -1, agent_pid = -1;
	struct cmp_child_report arep = {};
	struct cmp_agent_report greport = {};
	struct cmp_snapshot pre = {}, post = {};
	struct memcg_async_reclaim *skel = NULL;
	struct bpf_program *member_prog = NULL;
	struct bpf_link *link = NULL;
	enum cmp_trigger trigger = CMP_TRIG_TIMER;
	enum cmp_impl impl;
	__u64 a_id = 0, t_burst = 0, first_protect_ns;
	__u64 rt_pre = 0, rc_pre = 0, rt_post = 0, rc_post = 0;
	__u64 hook_calls = 0, hook_pre = 0, requests = 0, poll_ticks = 0;
	__u64 acquire_fails = 0, timer_failures = 0;

	LIBBPF_OPTS(bpf_test_run_opts, run_opts);
	const char *dir;
	double deadline;
	char fmtb[32];

	if (!o->impl_str || cmp_parse_impl(o->impl_str, &impl)) {
		fprintf(stderr, "ERROR: cmp needs --impl user|bpf-poll|bpf-hook|sanity\n");
		return 1;
	}
	if (o->trigger_str && cmp_parse_trigger(o->trigger_str, &trigger)) {
		fprintf(stderr, "ERROR: --trigger must be timer or poll\n");
		return 1;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	printf("cmp: impl=%s trigger=%s interval=%lums rate=%lu/s hysteresis=%lums read-cycle=%lums filler-sleep=%lums\n",
	       o->impl_str, cmp_trigger_str(trigger), o->interval_ms,
	       o->threshold, o->hysteresis_ms, o->read_cycle_ms,
	       o->filler_sleep_ms);
	fmt_bytes(fmtb, sizeof(fmtb), o->tmax);
	printf("     tmax=%s", fmtb);
	fmt_bytes(fmtb, sizeof(fmtb), o->budget);
	printf(" budget=%s", fmtb);
	fmt_bytes(fmtb, sizeof(fmtb), o->filler_bytes);
	printf(" filler=%s", fmtb);
	fmt_bytes(fmtb, sizeof(fmtb), o->burst_bytes);
	printf(" burst=%s", fmtb);
	fmt_bytes(fmtb, sizeof(fmtb), o->file_size);
	printf(" a-file=%s", fmtb);
	fmt_bytes(fmtb, sizeof(fmtb), o->agent_min);
	printf(" agent-min=%s\n", fmtb);
	printf("     ramp=%lus duration=%lus\n", o->ramp_sec, o->duration_sec);
	if (!o->burst_bytes)
		fprintf(stderr, "WARNING: --burst 0: no anon ballast; T's file pool\n"
			"         grows and A takes a smaller share of the scan.\n");

	if (cmp_setup_topology(o))
		goto out;

	a_id = cgroup_id_from_path(CMP_A_DIR);
	if (!a_id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", CMP_A_DIR,
			strerror(errno));
		goto out;
	}

	/*
	 * Without psi=1 (CONFIG_PSI_DEFAULT_DISABLED=y kernels) memory.pressure
	 * does not exist: the poll agent could never arm, and every PSI column
	 * would silently read 0 - which once masqueraded as "A never stalls".
	 */
	if (access(CMP_A_DIR "/memory.pressure", R_OK | W_OK)) {
		if (trigger == CMP_TRIG_POLL) {
			fprintf(stderr, "ERROR: %s/memory.pressure unavailable (%s):\n"
				"       --trigger poll needs PSI; boot with psi=1\n",
				CMP_A_DIR, strerror(errno));
			goto out;
		}
		fprintf(stderr, "WARNING: memory.pressure unavailable (%s) - PSI\n"
			"         columns read 0; boot with psi=1 to fill them.\n",
			strerror(errno));
	}

	if (impl != CMP_IMPL_USER) {
		struct cmp_cfg cfg = {
			.enabled		= 1,
			.monitor_cgroup_id	= a_id,
			.interval_ns		= impl == CMP_IMPL_BPF_POLL ?
				(__u64)o->interval_ms * 1000000ULL : 0,
			.drop_rate		= o->threshold,
			.hysteresis_ns		= (__u64)o->hysteresis_ms * 1000000ULL,
			.page_size		= (__u64)sysconf(_SC_PAGESIZE),
		};
		__u32 zero = 0;

		skel = memcg_async_reclaim__open_and_load();
		if (!skel) {
			fprintf(stderr, "ERROR: failed to open or load the BPF object\n");
			goto out;
		}

		if (bpf_map_update_elem(bpf_map__fd(skel->maps.cmp_cfg),
					&zero, &cfg, 0)) {
			fprintf(stderr, "ERROR: cmp_cfg update: %s\n",
				strerror(errno));
			goto out;
		}

		a_dir_fd = open(CMP_A_DIR, O_RDONLY);
		if (a_dir_fd < 0) {
			log_err("opening %s", CMP_A_DIR);
			goto out;
		}

		switch (impl) {
		case CMP_IMPL_BPF_POLL:
			link = bpf_map__attach_cgroup_opts(
				skel->maps.cmp_prot_ops_poll, a_dir_fd, NULL);
			member_prog = skel->progs.cmp_low_request_poll;
			break;
		case CMP_IMPL_BPF_HOOK:
			link = bpf_map__attach_cgroup_opts(
				skel->maps.cmp_prot_ops_hook, a_dir_fd, NULL);
			member_prog = skel->progs.cmp_low_request_hook;
			break;
		case CMP_IMPL_SANITY:
			link = bpf_map__attach_cgroup_opts(
				skel->maps.cmp_prot_ops_sanity, a_dir_fd, NULL);
			member_prog = skel->progs.cmp_low_request_sanity;
			break;
		default:
			break;
		}
		if (!link) {
			fprintf(stderr, "ERROR: attach to %s failed: %s\n",
				CMP_A_DIR, strerror(errno));
			goto out;
		}

		/* Seeds the B-arm baselines; starts the B1 timer. */
		init_fd = bpf_program__fd(skel->progs.cmp_prot_init);
		if (bpf_prog_test_run_opts(init_fd, &run_opts) ||
		    run_opts.retval) {
			fprintf(stderr, "ERROR: cmp_prot_init failed: %s (retval %d)\n",
				errno ? strerror(errno) : "-",
				run_opts.retval);
			goto out;
		}
	}

	dir = workload_files_dir();
	if (!dir) {
		fprintf(stderr, "ERROR: no writable non-tmpfs directory for the workload files\n");
		goto out;
	}
	snprintf(a_data, sizeof(a_data), "%s/cmp_a_data_XXXXXX", dir);
	snprintf(b_data, sizeof(b_data), "%s/cmp_b_data_XXXXXX", dir);
	snprintf(a_rep, sizeof(a_rep), "%s/cmp_a_rep_XXXXXX", dir);
	snprintf(g_rep, sizeof(g_rep), "%s/cmp_g_rep_XXXXXX", dir);
	a_data_fd = mkstemp(a_data);
	b_data_fd = mkstemp(b_data);
	a_rep_fd = mkstemp(a_rep);
	g_rep_fd = mkstemp(g_rep);
	if (a_data_fd < 0 || b_data_fd < 0 || a_rep_fd < 0 || g_rep_fd < 0) {
		fprintf(stderr, "ERROR: mkstemp: %s\n", strerror(errno));
		goto out;
	}

	b_pid = fork();
	if (b_pid == 0)
		_exit(cmp_child_filler(CMP_B_DIR, b_data_fd, o->filler_bytes,
				       o->filler_sleep_ms));
	if (b_pid < 0) {
		fprintf(stderr, "ERROR: fork filler: %s\n", strerror(errno));
		goto out;
	}

	a_pid = fork();
	if (a_pid == 0)
		_exit(cmp_child_reader(CMP_A_DIR, a_data_fd, a_rep_fd,
				       o->file_size, o->read_cycle_ms));
	if (a_pid < 0) {
		fprintf(stderr, "ERROR: fork reader: %s\n", strerror(errno));
		goto out;
	}

	if (impl == CMP_IMPL_USER) {
		struct cmp_agent_cfg ac = {
			.use_poll	= trigger == CMP_TRIG_POLL,
			.interval_ms	= o->interval_ms,
			.psi_us		= o->psi_us,
			.page_size	= (unsigned long)sysconf(_SC_PAGESIZE),
			.rate		= o->threshold,
			.hysteresis_ns	= (__u64)o->hysteresis_ms * 1000000ULL,
		};

		agent_pid = fork();
		if (agent_pid == 0)
			_exit(cmp_child_agent(&ac, g_rep_fd));
		if (agent_pid < 0) {
			fprintf(stderr, "ERROR: fork agent: %s\n",
				strerror(errno));
			goto out;
		}
	}

	/* Ramp: let B's cache build and A settle into its read loop before
	 * anything is measured or protected.
	 */
	deadline = now_sec() + o->ramp_sec;
	while (!READ_ONCE(exiting) && now_sec() < deadline)
		usleep(POLL_SLICE_MS * 1000);

	if (impl != CMP_IMPL_USER) {
		cmp_set_bpf_stats(1, &stats_prev);
		if (member_prog)
			cmp_prog_run_info(member_prog, &rt_pre, &rc_pre);
	}
	cmp_take_snapshot(&pre);
	if (skel)
		hook_pre = skel->bss->cmp_hook_calls;

	t_burst = mono_ns();
	if (o->burst_bytes) {
		c_pid = fork();
		if (c_pid == 0)
			_exit(cmp_child_burst(CMP_C_DIR, o->burst_bytes));
		if (c_pid < 0) {
			fprintf(stderr, "ERROR: fork burst: %s\n",
				strerror(errno));
			goto stop;
		}
	}

	deadline = now_sec() + o->duration_sec;
	while (!READ_ONCE(exiting) && now_sec() < deadline)
		usleep(POLL_SLICE_MS * 1000);

stop:
	cmp_take_snapshot(&post);
	if (member_prog)
		cmp_prog_run_info(member_prog, &rt_post, &rc_post);

	if (agent_pid > 0)
		kill(agent_pid, SIGTERM);
	if (c_pid > 0)
		kill(c_pid, SIGTERM);
	if (a_pid > 0)
		kill(a_pid, SIGTERM);
	if (b_pid > 0)
		kill(b_pid, SIGTERM);
	if (agent_pid > 0)
		reap_child(&agent_pid, "agent");
	if (c_pid > 0)
		reap_child(&c_pid, "burst");
	if (a_pid > 0)
		reap_child(&a_pid, "reader");
	if (b_pid > 0)
		reap_child(&b_pid, "filler");

	if (cmp_read_report(a_rep_fd, &arep, sizeof(arep)))
		fprintf(stderr, "WARNING: no reader report\n");
	if (impl == CMP_IMPL_USER &&
	    cmp_read_report(g_rep_fd, &greport, sizeof(greport)))
		fprintf(stderr, "WARNING: no agent report\n");

	if (skel) {
		hook_calls = skel->bss->cmp_hook_calls;
		requests = skel->bss->cmp_requests;
		poll_ticks = skel->bss->cmp_poll_ticks;
		acquire_fails = skel->bss->cmp_acquire_fails;
		timer_failures = skel->bss->cmp_timer_failures;
		first_protect_ns = skel->bss->cmp_first_request_ns;
	} else {
		first_protect_ns = greport.first_protect_ns;
	}

	/*
	 * A round in which protection never engaged measures nothing: the
	 * arms would be identical by construction. Flag it instead of
	 * letting it into the statistics.
	 *
	 * Sanity additionally requires the hook to have been called inside
	 * the window (the burst did drive reclaim through A's protection
	 * calculation) and A to have kept essentially all of its pages. Not
	 * exactly all: during C's charge storm a reclaim pass occasionally
	 * cannot be satisfied from B's young tail and dips through the
	 * protection (MEMCG_LOW overrides), which leaks a few pages under
	 * any protection shape - unconditional requests included. Allow up
	 * to 1/8 of A's file: a broken chain loses the whole working set
	 * (thousands of pages per read pass), so the gate still separates
	 * cleanly. A's memory.events "low" is NOT the gate: the kernel only
	 * counts MEMCG_LOW when reclaim overrides the protection on a
	 * second pass, so it stays 0 for as long as B supplies enough
	 * unprotected memory - which is the protection working, not failing.
	 */
	valid = first_protect_ns != 0;
	if (impl == CMP_IMPL_SANITY)
		valid = valid && hook_calls > hook_pre &&
			post.steal_a - pre.steal_a <=
				o->file_size / 4096 / 8;

	printf("\n--- result (window = %.1fs burst phase) ---\n",
	       (double)(mono_ns() - t_burst) / 1e9);
	printf("A: pgsteal +%llu pages, refault +%llu KiB, low overrides +%llu, PSI some +%llu us, current %llu KiB\n",
	       post.steal_a - pre.steal_a,
	       (post.refault_a - pre.refault_a) / 1024,
	       post.low_events_a - pre.low_events_a,
	       post.psi_a_us - pre.psi_a_us, post.cur_a / 1024);
	printf("A: reads %llu, avg %llu us, max %llu us\n",
	       (unsigned long long)arep.iters,
	       arep.iters ? (unsigned long long)(arep.sum_ns / arep.iters / 1000) : 0ULL,
	       (unsigned long long)(arep.max_ns / 1000));
	printf("B: PSI some +%llu us, current %llu KiB\n",
	       post.psi_b_us - pre.psi_b_us, post.cur_b / 1024);
	if (first_protect_ns)
		printf("first protection: %+.1f ms from burst start%s\n",
		       ((double)first_protect_ns - (double)t_burst) / 1e6,
		       valid ? "" : " - ROUND VOID (see sanity line)");
	else
		printf("first protection: never - ROUND VOID (trigger not reached)\n");

	if (impl == CMP_IMPL_USER) {
		printf("agent: decisions %llu, low writes %llu, sample avg %llu us max %llu us\n",
		       (unsigned long long)greport.decisions,
		       (unsigned long long)greport.writes,
		       greport.decisions ? (unsigned long long)(greport.sample_sum_ns / greport.decisions / 1000) : 0ULL,
		       (unsigned long long)(greport.sample_max_ns / 1000));
		printf("agent cpu: %llu us (agent cgroup), A cpu %llu us, B cpu %llu us, C cpu %llu us\n",
		       post.cpu_agent_us - pre.cpu_agent_us,
		       post.cpu_a_us - pre.cpu_a_us,
		       post.cpu_b_us - pre.cpu_b_us,
		       post.cpu_c_us - pre.cpu_c_us);
	} else {
		printf("bpf: hook calls %llu, requests %llu, poll ticks %llu, acquire fails %llu, timer fails %llu\n",
		       (unsigned long long)hook_calls,
		       (unsigned long long)requests,
		       (unsigned long long)poll_ticks,
		       (unsigned long long)acquire_fails,
		       (unsigned long long)timer_failures);
		if (rc_post > rc_pre)
			printf("bpf: hook run_time %llu ns over %llu runs (avg %llu ns)\n",
			       (unsigned long long)(rt_post - rt_pre),
			       (unsigned long long)(rc_post - rc_pre),
			       (unsigned long long)((rt_post - rt_pre) / (rc_post - rc_pre)));
		else
			printf("bpf: hook run_time unavailable (kernel.bpf_stats_enabled?)\n");
		printf("cpu: A %llu us, B %llu us, C %llu us\n",
		       post.cpu_a_us - pre.cpu_a_us,
		       post.cpu_b_us - pre.cpu_b_us,
		       post.cpu_c_us - pre.cpu_c_us);
	}
	if (impl == CMP_IMPL_SANITY)
		printf("sanity: %s (hook calls %llu in window, A pgsteal +%llu pages, tol %llu, refault +%llu KiB, low overrides +%llu)\n",
		       valid ? "PASS" : "FAIL",
		       (unsigned long long)(hook_calls - hook_pre),
		       (unsigned long long)(post.steal_a - pre.steal_a),
		       (unsigned long long)(o->file_size / 4096 / 8),
		       (unsigned long long)((post.refault_a - pre.refault_a) / 1024),
		       (unsigned long long)(post.low_events_a - pre.low_events_a));
	if (acquire_fails)
		fprintf(stderr, "WARNING: %llu acquire-route failures in the B1 sampler\n",
			(unsigned long long)acquire_fails);
	if (timer_failures)
		fprintf(stderr, "WARNING: B1 timer rearm failed %llu time(s)\n",
			(unsigned long long)timer_failures);

	if (o->csv_path) {
		FILE *f = fopen(o->csv_path, "a");

		if (!f) {
			fprintf(stderr, "WARNING: cannot append to %s: %s\n",
				o->csv_path, strerror(errno));
		} else {
			if (!ftell(f))
				fprintf(f, "ts,impl,trigger,interval_ms,psi_us,rate_pps,read_cycle_ms,filler_sleep_ms,hysteresis_ms,duration_sec,burst,budget,tmax,steal_a_pages,refault_a_kib,low_a,psi_a_us,psi_b_us,cur_a_kib,first_protect_ms,decisions,writes,hook_calls,requests,poll_ticks,acquire_fails,run_time_ns,run_cnt,a_iters,a_avg_us,a_max_us,agent_avg_us,agent_max_us,cpu_a_us,cpu_b_us,cpu_c_us,cpu_agent_us,valid\n");
			fprintf(f, "%lld,%s,%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%llu,%llu,%llu,%llu,%llu,%llu,%.3f,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d\n",
				(long long)time(NULL), o->impl_str,
				cmp_trigger_str(trigger), o->interval_ms,
				o->psi_us, o->threshold, o->read_cycle_ms,
				o->filler_sleep_ms, o->hysteresis_ms,
				o->duration_sec,
				o->burst_bytes, o->budget, o->tmax,
				post.steal_a - pre.steal_a,
				(post.refault_a - pre.refault_a) / 1024,
				post.low_events_a - pre.low_events_a,
				post.psi_a_us - pre.psi_a_us,
				post.psi_b_us - pre.psi_b_us,
				post.cur_a / 1024,
				valid ? ((double)first_protect_ns - (double)t_burst) / 1e6 : -1.0,
				greport.decisions, greport.writes,
				hook_calls, requests, poll_ticks,
				acquire_fails, rt_post - rt_pre,
				rc_post - rc_pre, arep.iters,
				arep.iters ? arep.sum_ns / arep.iters / 1000 : 0,
				arep.max_ns / 1000,
				greport.decisions ? greport.sample_sum_ns / greport.decisions / 1000 : 0,
				greport.sample_max_ns / 1000,
				post.cpu_a_us - pre.cpu_a_us,
				post.cpu_b_us - pre.cpu_b_us,
				post.cpu_c_us - pre.cpu_c_us,
				post.cpu_agent_us - pre.cpu_agent_us,
				valid);
			fclose(f);
		}
	}

	ret = 0;

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		memcg_async_reclaim__destroy(skel);
	if (stats_prev >= 0)
		cmp_set_bpf_stats(stats_prev, NULL);
	if (a_dir_fd >= 0)
		close(a_dir_fd);
	if (a_data_fd >= 0) {
		close(a_data_fd);
		unlink(a_data);
	}
	if (b_data_fd >= 0) {
		close(b_data_fd);
		unlink(b_data);
	}
	if (a_rep_fd >= 0) {
		close(a_rep_fd);
		unlink(a_rep);
	}
	if (g_rep_fd >= 0) {
		close(g_rep_fd);
		unlink(g_rep);
	}
	cmp_teardown_cgroups();

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
	       "  watch    watch an existing cgroup and reclaim from another one\n"
	       "           whenever it comes under pressure, until interrupted\n"
	       "  cmp      run one arm of the three-arm memory.low request\n"
	       "           comparison - userspace agent (user), bpf_wq poller\n"
	       "           (bpf-poll), in-hook decision (bpf-hook) - against a\n"
	       "           freshly built topology, and report the burst window\n\n"
	       "Common options:\n"
	       "  -i, --interval MS     monitor tick (bench: %d, watch: %d, cmp: %d)\n"
	       "  -t, --threshold N     refault delta per tick that starts a round (%d)\n"
	       "                        cmp: A usage-drop pages per second, all arms (%lu)\n"
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
	       "  -T, --target PATH     cgroup to reclaim from (required)\n"
	       "  -D, --duration SEC    stop after SEC seconds instead of on signal\n"
	       "  -s, --stats SEC       print a statistics line every SEC seconds (%d)\n\n"
	       "cmp options:\n"
	       "      --impl IMPL       user | bpf-poll | bpf-hook | sanity (required)\n"
	       "      --trigger T       U arm wakeup: timer (default) or poll (PSI;\n"
	       "                        needs the kernel booted with psi=1)\n"
	       "      --psi-us N        poll trigger: stall us per 1s window (%d)\n"
	       "      --hysteresis MS   hold protection this long after the evidence\n"
	       "                        stops (%d)\n"
	       "      --read-cycle MS   A paces its re-read passes to this cycle (%d)\n"
	       "      --filler-sleep MS B pauses this long between rewrite passes (%d)\n"
	       "      --budget BYTES    T memory.low, shields the subtree against\n"
	       "                        global reclaim (%luM)\n"
	       "      --tmax BYTES      T memory.max, the pressure source (%luM)\n"
	       "      --filler BYTES    B's file, rewritten in a loop: the renewable\n"
	       "                        unprotected reclaim fodder (%luM)\n"
	       "      --burst BYTES     C's one-shot anon ballast; 0 runs without (0)\n"
	       "      --ramp SEC        settle time before the measured window (%d)\n"
	       "      --agent-min BYTES agent cgroup memory.min, disclosed (%luM)\n"
	       "      --csv FILE        append one result row per run\n"
	       "  -f, -D and -v are shared: A's file size, window length, chatter\n\n"
	       "BYTES accepts a K, M or G suffix. All modes need root.\n\n"
	       "One call to bpf_proactive_reclaim() reclaims at most the kernel's\n"
	       "MEMCG_CHARGE_BATCH pages, so --batch above that limit only means a\n"
	       "round needs more callbacks, not that a single callback does more.\n",
	       prog, BENCH_INTERVAL_MS, WATCH_INTERVAL_MS,
	       DEFAULT_CMP_INTERVAL_MS, DEFAULT_THRESHOLD,
	       DEFAULT_CMP_RATE,
	       DEFAULT_BATCH_BYTES / 1024, DEFAULT_MAX_BATCHES,
	       DEFAULT_SWAPPINESS, DEFAULT_CG_LIMIT / (1024 * 1024),
	       DEFAULT_FILE_SIZE / (1024 * 1024), DEFAULT_READ_TIMES,
	       DEFAULT_STATS_SEC, DEFAULT_CMP_PSI_US,
	       DEFAULT_CMP_HYSTERESIS_MS, DEFAULT_CMP_READ_CYCLE_MS,
	       DEFAULT_CMP_FILLER_SLEEP_MS,
	       DEFAULT_CMP_BUDGET / (1024 * 1024),
	       DEFAULT_CMP_TMAX / (1024 * 1024),
	       DEFAULT_CMP_FILLER / (1024 * 1024), DEFAULT_CMP_RAMP_SEC,
	       DEFAULT_CMP_AGENT_MIN / (1024 * 1024));
}

enum {
	OPT_NO_BASELINE = 256,
	OPT_IMPL,
	OPT_TRIGGER,
	OPT_CSV,
	OPT_PSI_US,
	OPT_HYSTERESIS,
	OPT_READ_CYCLE,
	OPT_FILLER_SLEEP,
	OPT_BUDGET,
	OPT_TMAX,
	OPT_FILLER,
	OPT_BURST,
	OPT_RAMP,
	OPT_AGENT_MIN,
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
		{ "impl",	required_argument,	NULL, OPT_IMPL },
		{ "trigger",	required_argument,	NULL, OPT_TRIGGER },
		{ "csv",		required_argument,	NULL, OPT_CSV },
		{ "psi-us",	required_argument,	NULL, OPT_PSI_US },
		{ "hysteresis",	required_argument,	NULL, OPT_HYSTERESIS },
		{ "read-cycle",	required_argument,	NULL, OPT_READ_CYCLE },
		{ "filler-sleep", required_argument,	NULL, OPT_FILLER_SLEEP },
		{ "budget",	required_argument,	NULL, OPT_BUDGET },
		{ "tmax",	required_argument,	NULL, OPT_TMAX },
		{ "filler",	required_argument,	NULL, OPT_FILLER },
		{ "burst",	required_argument,	NULL, OPT_BURST },
		{ "ramp",	required_argument,	NULL, OPT_RAMP },
		{ "agent-min",	required_argument,	NULL, OPT_AGENT_MIN },
		{ }
	};
	int c;

	while ((c = getopt_long(argc, argv, "i:t:b:n:S:vhl:f:R:m:T:D:s:",
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
		case OPT_IMPL:
			o->impl_str = optarg;
			break;
		case OPT_TRIGGER:
			o->trigger_str = optarg;
			break;
		case OPT_CSV:
			o->csv_path = optarg;
			break;
		case OPT_PSI_US:
			if (parse_ulong(optarg, &o->psi_us))
				return -1;
			break;
		case OPT_HYSTERESIS:
			if (parse_ulong(optarg, &o->hysteresis_ms))
				return -1;
			break;
		case OPT_READ_CYCLE:
			if (parse_ulong(optarg, &o->read_cycle_ms))
				return -1;
			break;
		case OPT_FILLER_SLEEP:
			if (parse_ulong(optarg, &o->filler_sleep_ms))
				return -1;
			break;
		case OPT_BUDGET:
			if (parse_size(optarg, &o->budget))
				return -1;
			break;
		case OPT_TMAX:
			if (parse_size(optarg, &o->tmax))
				return -1;
			break;
		case OPT_FILLER:
			if (parse_size(optarg, &o->filler_bytes))
				return -1;
			break;
		case OPT_BURST:
			if (parse_size(optarg, &o->burst_bytes))
				return -1;
			break;
		case OPT_RAMP:
			if (parse_ulong(optarg, &o->ramp_sec))
				return -1;
			break;
		case OPT_AGENT_MIN:
			if (parse_size(optarg, &o->agent_min))
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
		.file_size = DEFAULT_FILE_SIZE,
		.read_times = DEFAULT_READ_TIMES,
		.stats_sec = DEFAULT_STATS_SEC,
		/* Pre-set, not filled in after parsing like the other cmp
		 * knobs: an explicit 0 is a legal calibration choice here
		 * (tight reader loop / full-rate filler).
		 */
		.read_cycle_ms = DEFAULT_CMP_READ_CYCLE_MS,
		.filler_sleep_ms = DEFAULT_CMP_FILLER_SLEEP_MS,
	};
	const char *mode;
	bool bench, cmp;

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
	cmp = !strcmp(mode, "cmp");
	if (!bench && !cmp && strcmp(mode, "watch")) {
		fprintf(stderr, "ERROR: unknown mode '%s', expected bench, watch or cmp\n\n",
			mode);
		usage(argv[0]);
		return 1;
	}

	/* Let getopt_long see the options rather than the mode. */
	optind = 2;
	if (parse_options(argc, argv, &o)) {
		usage(argv[0]);
		return 1;
	}

	if (!o.interval_ms)
		o.interval_ms = cmp ? DEFAULT_CMP_INTERVAL_MS :
				bench ? BENCH_INTERVAL_MS : WATCH_INTERVAL_MS;
	if (!o.stats_sec)
		o.stats_sec = DEFAULT_STATS_SEC;
	if (cmp) {
		/* Zero means "not given" for every cmp knob except --burst,
		 * where 0 is a legal steady-state choice.
		 */
		if (!o.duration_sec)
			o.duration_sec = DEFAULT_CMP_DURATION_SEC;
		if (!o.ramp_sec)
			o.ramp_sec = DEFAULT_CMP_RAMP_SEC;
		if (!o.hysteresis_ms)
			o.hysteresis_ms = DEFAULT_CMP_HYSTERESIS_MS;
		if (!o.psi_us)
			o.psi_us = DEFAULT_CMP_PSI_US;
		if (!o.budget)
			o.budget = DEFAULT_CMP_BUDGET;
		if (!o.tmax)
			o.tmax = DEFAULT_CMP_TMAX;
		if (!o.filler_bytes)
			o.filler_bytes = DEFAULT_CMP_FILLER;
		if (!o.agent_min)
			o.agent_min = DEFAULT_CMP_AGENT_MIN;
		/* -t defaults to 1 refault byte for the reclaim demo; cmp's
		 * evidence is A's memory.current fall in pages per second, so
		 * cmp's own default applies unless the user gave -t
		 * explicitly. A user passing -t 1 for cmp gets what they
		 * asked for.
		 */
		if (o.threshold == DEFAULT_THRESHOLD)
			o.threshold = DEFAULT_CMP_RATE;
	}
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

	return cmp ? do_cmp(&o) : bench ? do_bench(&o) : do_watch(&o);
}
