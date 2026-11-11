/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between memcg_async_reclaim.bpf.c and memcg_async_reclaim_user.c.
 *
 * Both sides must have pulled in their type headers first: vmlinux.h for the
 * BPF program, <linux/types.h> (via test_progs.h or libbpf) for the loader.
 */
#ifndef __MEMCG_ASYNC_RECLAIM_H
#define __MEMCG_ASYNC_RECLAIM_H

struct reclaim_cfg {
	/* Cgroup whose refaults are watched, i.e. the one under pressure. */
	__u64 monitor_cgroup_id;
	/* Cgroup that gets reclaimed from when the monitor refaults. */
	__u64 target_cgroup_id;
	/* Refault delta per tick that starts a reclaim round. */
	__u64 refault_threshold;
	/* Monitor tick period, in nanoseconds. */
	__u64 interval_ns;
	/* Bytes requested per bpf_wq callback. */
	__u64 batch_bytes;
	/* Callbacks per reclaim round. */
	__u64 max_batches;
	/* Passed through to bpf_proactive_reclaim(): -1, 0..200, or 201. */
	__s64 swappiness;
};

/* Outcome of a single reclaim attempt, reported through the ringbuf. */
enum reclaim_outcome {
	RECLAIM_OUTCOME_CALLED,
	RECLAIM_OUTCOME_SKIPPED_DYING,
	RECLAIM_OUTCOME_TARGET_GONE,
};

struct reclaim_event {
	__u64 outcome;
};

/*
 * Configuration of the cmp three-arm comparison, written by the loader into
 * the cmp_cfg array map before the struct_ops program is attached and before
 * cmp_prot_init() runs. Runtime-writable (array maps are not frozen), so the
 * loader can also disable everything by clearing @enabled.
 */
struct cmp_cfg {
	/* 0 = every cmp hook reports no request. */
	__u64 enabled;
	/* Cgroup the evidence is collected for (cgroup A). */
	__u64 monitor_cgroup_id;
	/* B1 poll tick; 0 for hook-only arms (B2, sanity). */
	__u64 interval_ns;
	/* A memory.current fall, in pages per second, that turns protection
	 * on (all arms; policy.h rate-normalizes, so sample frequency does
	 * not matter).
	 */
	__u64 drop_rate;
	/* Hold protection this long after the evidence stops. */
	__u64 hysteresis_ns;
	/* The loader's page size: bpf_mem_cgroup_usage() returns bytes while
	 * ctx->usage and the policy work in pages.
	 */
	__u64 page_size;
};

#endif /* __MEMCG_ASYNC_RECLAIM_H */
