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
 * watch mode method selectors, one bitmask each so the methods stack.
 *
 * low and min name the same bpf_memcg_ops hook on both sides: observing it
 * means treating the kernel consulting the hook as the pressure signal,
 * controlling it means answering BELOW so reclaim skips the monitor cgroup.
 * They stay separate values because the two differ in kind - min is hard and
 * can OOM whatever else is in the hierarchy, low is soft and yields when
 * nothing else can be reclaimed.
 */
#define OBS_REFAULT	(1u << 0)	/* timer polls workingset refaults */
#define OBS_LOW		(1u << 1)	/* low_policy was consulted */
#define OBS_MIN		(1u << 2)	/* min_policy was consulted */

#define CTL_RECLAIM	(1u << 0)	/* bpf_proactive_reclaim() the target */
#define CTL_LOW		(1u << 1)	/* low_policy answers BELOW */
#define CTL_MIN		(1u << 2)	/* min_policy answers BELOW */

#endif /* __MEMCG_ASYNC_RECLAIM_H */
