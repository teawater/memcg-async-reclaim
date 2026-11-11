/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The decision policy shared by all three arms of the cmp comparison.
 *
 * The whole point of the comparison is that U (userspace agent), B1 (bpf_wq
 * poller) and B2 (in-hook decision) run the *same* integer arithmetic on the
 * *same* counter - A's memory.current, the page_counter the kernel charges
 * and uncharges synchronously - and differ only in where the code runs and
 * how often it samples: U preads memory.current from a userspace loop, B1
 * reads bpf_mem_cgroup_usage() from a wq tick, B2 reads ctx->usage on every
 * protection pass from inside the hook. Any difference in outcome therefore
 * comes from placement and sampling, not from a smarter rule on one side.
 *
 * The evidence is the counter's *fall*: reclaim uncharges A in-pass, so a
 * dropping usage means "A is being stolen from" with no statistics-flush
 * dependency in between. (This is why the first calibration's evidence,
 * pgsteal, failed for B2: BPF can only read it from the flushed global
 * counters, nothing flushes inside a reclaim pass, and the counter B2 saw
 * advanced in multi-second steps - a whole burst window passed with zero
 * requests while A lost 19k pages.) A rising usage is A charging its own
 * refaults - self-recovery, not pressure - so only falls count as evidence.
 *
 * The threshold is a *rate* (evidence pages per second), and each sample's
 * fall is scaled by the time since the previous sample. A per-sample
 * threshold would not be arm-independent: B2 samples on every protection
 * pass (sub-millisecond apart during a reclaim storm) while U/B1 sample on a
 * fixed tick, so the same nominal threshold would demand a ~10x higher
 * evidence rate from B2 - a calibration artifact, not a property of the
 * arms. Rate normalization keeps one shared parameter and makes every arm
 * trigger on the same physical evidence rate.
 *
 * Pure integers, no libc, no branches on pointers: includable from both the
 * BPF object (after vmlinux.h) and the loader (after <linux/types.h>).
 */
#ifndef __POLICY_H
#define __POLICY_H

#define POLICY_NSEC_PER_SEC 1000000000ULL

struct policy_state {
	/* A's memory.current in pages, as observed at the previous sample. */
	__u64 prev_level;
	/* Timestamp of the previous sample; callers must seed this with the
	 * seed-time clock value, or the first sample's rate is diluted over
	 * the whole clock epoch.
	 */
	__u64 prev_ns;
	/*
	 * Monotonic timestamp (ns) of the most recent sample that carried new
	 * evidence; 0 means "not protecting". Callers must pass a clock that
	 * never returns 0 (bpf_ktime_get_ns / CLOCK_MONOTONIC both qualify).
	 */
	__u64 on_since;
};

/*
 * Decide whether the watched cgroup should be protected right now.
 *
 * @level is A's memory.current in pages at @now_ns. Protection turns on when
 * the level has fallen by at least @threshold_rate pages per second since the
 * previous sample, and stays on while the fall continues; once it stops,
 * protection is held for @hysteresis_ns and then dropped. Rises only reset
 * the baseline; they are never evidence. A seed failure (prev_level left at
 * 0) therefore degrades to "first sample has no evidence", never to a
 * spurious trigger.
 */
static inline int policy_protect(struct policy_state *st, __u64 level,
				 __u64 now_ns, __u64 threshold_rate,
				 __u64 hysteresis_ns)
{
	__u64 drop = st->prev_level > level ? st->prev_level - level : 0;
	__u64 elapsed = now_ns - st->prev_ns;

	st->prev_level = level;
	st->prev_ns = now_ns;
	if (!elapsed)
		elapsed = 1;

	/* drop / elapsed >= rate, cross-multiplied; both sides fit u64 for
	 * any realistic level (<= ~1e7 pages) and interval (<= ~100s).
	 */
	if (drop * POLICY_NSEC_PER_SEC >= threshold_rate * elapsed) {
		st->on_since = now_ns;
		return 1;
	}

	if (st->on_since && now_ns - st->on_since >= hysteresis_ns) {
		st->on_since = 0;
		return 0;
	}

	return st->on_since != 0;
}

#endif /* __POLICY_H */
