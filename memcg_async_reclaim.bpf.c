// SPDX-License-Identifier: GPL-2.0
/*
 * Refault-driven asynchronous proactive reclaim.
 *
 * A bpf_timer ticks every cfg->interval_ns. On each tick a bpf_wq callback
 * checks whether the monitored cgroup refaulted enough to warrant reclaim; if
 * so it opens a round of up to cfg->max_batches batches and reclaims one batch
 * of cfg->batch_bytes per callback, requeueing itself until the round's budget
 * is spent. Nothing here blocks the monitored workload: the reclaim happens on
 * a workqueue, against a different cgroup.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "memcg_async_reclaim.h"
#include "policy.h"

#define CLOCK_MONOTONIC		1

struct cgroup_memcg {
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
};

static u64 wq_monitor_cgroup_id;
static u64 wq_target_cgroup_id;

/*
 * Statistics exposed to userspace through .bss, so that the loader can report
 * what actually happened instead of inferring it from timings.
 *
 * These are __u64 rather than u64 because bpftool emits the type name verbatim
 * into the generated skeleton, and the loader has no kernel typedefs.
 */
__u64 reclaim_calls;
__u64 reclaimed_bytes;

/*
 * Number of rounds started, i.e. ticks on which the monitored cgroup crossed
 * the refault threshold. A round spans up to max_batches callbacks, so this
 * tells the two apart: many calls per round means the target had a lot to
 * give, many rounds means the monitor keeps refaulting.
 */
__u64 reclaim_rounds;

/*
 * A timer that fails to rearm stops the whole chain, which from userspace looks
 * exactly like "nothing needed reclaiming". Count it so the two can be told
 * apart instead of blaming the workload.
 */
__u64 timer_failures;

/*
 * bpf_proactive_reclaim() reports failure as a negative return, which is
 * otherwise indistinguishable from "this cgroup has nothing left to reclaim".
 * Keep the last one so a failing kfunc is not mistaken for an idle cgroup.
 * Stored as a positive errno.
 */
__u64 last_reclaim_err;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} reclaim_events SEC(".maps");

/*
 * Reports are best effort: when the ringbuf is full, for example when
 * userspace does not consume the events, the report is dropped.
 */
static void emit_reclaim_event(enum reclaim_outcome outcome)
{
	struct reclaim_event *ev;

	ev = bpf_ringbuf_reserve(&reclaim_events, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->outcome = outcome;
	bpf_ringbuf_submit(ev, 0);
}

static int get_cgroup_memcg_from_id(u64 cgroup_id, struct cgroup_memcg *cm)
{
	cm->cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cm->cgrp)
		return -1;

	cm->memcg = bpf_get_mem_cgroup(&cm->cgrp->self);
	if (!cm->memcg) {
		bpf_cgroup_release(cm->cgrp);
		return -1;
	}

	return 0;
}

static void put_cgroup_memcg(struct cgroup_memcg *cm)
{
	bpf_put_mem_cgroup(cm->memcg);
	bpf_cgroup_release(cm->cgrp);
}

/*
 * Total workingset refaults of a cgroup, across memory types: the trigger
 * evidence of the async reclaim demo.
 *
 * Pressure shows up in the counter matching the memory the workload uses: a
 * page-cache workload refaults file pages, an anonymous one refaults anon.
 * Watching only either counter makes the trigger blind to the other kind of
 * workload, so sum them; for a workload that stresses one type only, the
 * other term stays 0.
 */
static int get_cgroup_refaults(u64 cgroup_id, u64 *val)
{
	struct cgroup_memcg cm;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return -1;
	bpf_mem_cgroup_flush_stats(cm.memcg);
	*val = bpf_mem_cgroup_page_state(cm.memcg,
		bpf_core_enum_value(enum node_stat_item,
				    WORKINGSET_REFAULT_FILE)) +
	       bpf_mem_cgroup_page_state(cm.memcg,
		bpf_core_enum_value(enum node_stat_item,
				    WORKINGSET_REFAULT_ANON));
	put_cgroup_memcg(&cm);

	return 0;
}

/*
 * A's memory.current in pages: the live page_counter the kernel charges and
 * uncharges synchronously, and the same counter all three cmp arms sample
 * (U preads memory.current, B1 reads it through bpf_mem_cgroup_usage(), B2
 * gets it as ctx->usage inside the hook). No rstat flush is involved - which
 * is exactly what pgsteal, the first calibration's evidence, could not offer
 * B2: its flushed global counters only advance in flush-sized steps, and
 * nothing flushes inside a reclaim pass. The kfunc returns bytes; the policy
 * and ctx->usage are in pages, so convert with the loader's page size.
 */
static int get_cgroup_usage_pages(u64 cgroup_id, u64 page_size, u64 *val)
{
	struct cgroup_memcg cm;

	if (!page_size)
		return -1;
	if (get_cgroup_memcg_from_id(cgroup_id, &cm))
		return -1;
	*val = bpf_mem_cgroup_usage(cm.memcg) / page_size;
	put_cgroup_memcg(&cm);

	return 0;
}

static bool
should_reclaim_cgroup(u64 cgroup_id, u64 *prev_refaults, u64 threshold)
{
	u64 cur, delta;

	if (get_cgroup_refaults(cgroup_id, &cur))
		return false;

	delta = cur - *prev_refaults;
	*prev_refaults = cur;

	return delta >= threshold;
}

/*
 * rmdir clears CSS_ONLINE on cgrp->self in cgroup_destroy_locked() and only
 * then deactivates the cgroup's kernfs node with kernfs_remove().
 * bpf_cgroup_from_id() resolves an id through
 * kernfs_find_and_get_node_by_id(), which refuses deactivated nodes, so the
 * lookup starts failing inside the rmdir syscall -- not, as one might expect,
 * once the cgroup's last reference has been dropped.
 *
 * The window in which the lookup still succeeds while the cgroup is already
 * dying is therefore just the few statements between those two. An attempt that
 * lands in it reports RECLAIM_OUTCOME_SKIPPED_DYING; after rmdir has returned,
 * every attempt reports TARGET_GONE instead. The check is kept because it is
 * the only thing standing between reclaim and a cgroup that is mid-teardown.
 *
 * Only CSS_ONLINE is worth testing. CSS_DYING is raised by kill_css_sync(),
 * which dereferences css->ss and so is never called with cgrp->self; the
 * cgroup's own css only ever loses CSS_ONLINE. This is therefore
 * cgroup_is_dead() from include/linux/cgroup.h, not css_is_dying().
 *
 * CSS_ONLINE comes from vmlinux.h: the kernel defines it in an anonymous enum,
 * so bpf_core_enum_value() has no enum type to bind to, and redeclaring it
 * locally would clash with the vmlinux.h enumerators. vmlinux.h is generated
 * from the running kernel's BTF, so the value already matches the target
 * kernel.
 */
static bool cgroup_is_dying(struct cgroup *cgrp)
{
	return !(cgrp->self.flags & CSS_ONLINE);
}

/*
 * Reclaim one batch from the target cgroup. Returns the number of bytes
 * reclaimed, or 0 if the cgroup is dying or gone, the kfunc failed, or nothing
 * was reclaimed. Each attempt reports its outcome through the reclaim_events
 * ringbuf, and a failing kfunc additionally records its errno in
 * last_reclaim_err.
 */
static u64 reclaim_cgroup(u64 cgroup_id, u64 size, int swappiness)
{
	struct cgroup_memcg cm;
	long nr;

	if (get_cgroup_memcg_from_id(cgroup_id, &cm)) {
		emit_reclaim_event(RECLAIM_OUTCOME_TARGET_GONE);
		return 0;
	}

	if (cgroup_is_dying(cm.cgrp)) {
		emit_reclaim_event(RECLAIM_OUTCOME_SKIPPED_DYING);
		put_cgroup_memcg(&cm);
		return 0;
	}

	reclaim_calls++;
	nr = bpf_proactive_reclaim(cm.memcg, size, swappiness);
	if (nr < 0)
		last_reclaim_err = -nr;
	else if (nr > 0)
		reclaimed_bytes += nr;
	emit_reclaim_event(RECLAIM_OUTCOME_CALLED);

	put_cgroup_memcg(&cm);

	return nr > 0 ? nr : 0;
}

struct wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 prev_refaults;
	u64 refault_threshold;
	u64 check_ns;
	u64 batch_bytes;
	u64 max_batches;
	int swappiness;
	/*
	 * Bytes still to reclaim in the current round, carried across requeues.
	 * 0 means no round is in progress; the timer path starts a new round by
	 * resetting it, requeued work only looks at it.
	 */
	u64 remaining;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct wq_elem);
} wq_map SEC(".maps");

/*
 * batch_bytes is a byte count, not a page count: bpf_proactive_reclaim()
 * converts it against the running kernel's PAGE_SIZE and returns bytes, so the
 * configuration holds on any page size. The kfunc also clamps a batch to the
 * kernel's MEMCG_CHARGE_BATCH, which is not visible to BPF; a clamped batch
 * only means a round needs more callbacks, because remaining is decremented by
 * the bytes actually reclaimed.
 */
static int reclaim_work_fn(void *map, int *key, void *value)
{
	struct wq_elem *elem = value;
	u64 nr, size;

	if (!elem->remaining) {
		/*
		 * Timer-triggered entry: start a new round only when the
		 * monitored cgroup refaults enough. Requeued entries skip this
		 * check and only look at remaining, so a round consumes the
		 * refault delta only on the tick that starts it; ticks that find
		 * no round in progress consume and discard it.
		 */
		if (!should_reclaim_cgroup(wq_monitor_cgroup_id,
					   &elem->prev_refaults,
					   elem->refault_threshold))
			return 0;
		elem->remaining = elem->max_batches * elem->batch_bytes;
		reclaim_rounds++;
	}

	/* One bounded reclaim pass per callback */
	size = elem->remaining < elem->batch_bytes ? elem->remaining
						   : elem->batch_bytes;
	nr = reclaim_cgroup(wq_target_cgroup_id, size, elem->swappiness);
	if (!nr) {
		elem->remaining = 0;
		return 0;
	}

	/* try_to_free_mem_cgroup_pages() may reclaim more than requested */
	if (nr >= elem->remaining)
		elem->remaining = 0;
	else
		elem->remaining -= nr;

	/* Requeue the same work item for the next batch */
	if (elem->remaining)
		bpf_wq_start(&elem->work, 0);

	return 0;
}

static int wq_timer_cb(void *map, int *key, struct wq_elem *elem)
{
	/*
	 * A failed bpf_wq_start() self-heals on the next tick; a failed rearm
	 * does not, so only the latter is worth reporting.
	 */
	bpf_wq_start(&elem->work, 0);
	if (bpf_timer_start(&elem->timer, elem->check_ns, 0))
		timer_failures++;

	return 0;
}

SEC("syscall")
int reclaim_prog_init(struct reclaim_cfg *ctx)
{
	struct wq_elem *elem;
	__u32 key = 0;
	int ret;

	elem = bpf_map_lookup_elem(&wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_wq_init(&elem->work, &wq_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(&elem->work, reclaim_work_fn, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &wq_map, CLOCK_MONOTONIC);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, wq_timer_cb);
	if (ret)
		return ret;

	elem->prev_refaults = 0;
	elem->remaining = 0;
	elem->refault_threshold = ctx->refault_threshold;
	elem->check_ns = ctx->interval_ns;
	elem->batch_bytes = ctx->batch_bytes;
	elem->max_batches = ctx->max_batches;
	elem->swappiness = ctx->swappiness;

	wq_monitor_cgroup_id = ctx->monitor_cgroup_id;
	wq_target_cgroup_id = ctx->target_cgroup_id;

	/*
	 * Seed the refault baseline instead of leaving it at 0: a cgroup that
	 * has been running for a while has a large counter already, and the
	 * first tick would otherwise read the whole history as new refaults and
	 * open a round nobody asked for. Failing to read it is not fatal, it
	 * only costs that first spurious round.
	 */
	get_cgroup_refaults(wq_monitor_cgroup_id, &elem->prev_refaults);

	return bpf_timer_start(&elem->timer, elem->check_ns, 0);
}

/*
 * cmp: three arms of the memory.low request comparison.
 *
 * All three arms watch A's memory.current and ask for protection when it
 * falls fast enough; they differ only in where the decision runs and how
 * the counter is sampled:
 *
 *   B1 (cmp_prot_ops_poll)  a bpf_timer ticks every cfg->interval_ns and a
 *                           bpf_wq callback samples the counter through
 *                           bpf_mem_cgroup_usage() and stores a boolean;
 *                           the hook only executes that verdict.
 *   B2 (cmp_prot_ops_hook)  the decision runs inside low_request itself, at
 *                           the collection point, on every protection pass,
 *                           on ctx->usage - the same page_counter, read live
 *                           by the kernel for this very pass. No kfunc, no
 *                           acquire route, no flush dependency.
 *   sanity (cmp_prot_ops_sanity)  requests unconditionally; used to verify
 *                           the protection chain end to end before a round.
 *
 * The userspace arm (U) lives entirely in the loader, preads the same
 * counter through memory.current, and shares policy.h. The hooks are
 * attached to A's cgroup only, so the effective-array walk already scopes
 * them to A; no cgroup id filter is needed.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cmp_cfg);
} cmp_cfg SEC(".maps");

/*
 * Run statistics, written by BPF only (userspace reads them after load; .bss
 * is frozen for userspace writes). cmp_first_request_ns is the ktime of the
 * first pass whose request was granted-worthy, which is the B-side analogue
 * of the agent's first memory.low write.
 */
__u64 cmp_hook_calls;
__u64 cmp_requests;
__u64 cmp_acquire_fails;
__u64 cmp_poll_ticks;
__u64 cmp_timer_failures;
__u64 cmp_first_request_ns;

/* B1: verdict decided by the wq callback, read by the hook. Plain u64
 * load/store; a torn read is impossible and a stale one lasts at most the
 * gap between a tick and a pass.
 */
static struct policy_state cmp_b1_state;
__u64 cmp_protect_now;

/* B2: decision state, updated inside the hook. */
static struct policy_state cmp_b2_state;

static struct cmp_cfg *cmp_cfg_lookup(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&cmp_cfg, &key);
}

static void cmp_note_request(void)
{
	__u64 now = bpf_ktime_get_ns();

	cmp_requests++;
	if (!cmp_first_request_ns)
		cmp_first_request_ns = now;
}

/* B1: one decision per tick; the reclaim batches of the async demo are not
 * part of this arm - the verdict is the only output.
 */
struct cmp_wq_elem {
	struct bpf_timer timer;
	struct bpf_wq work;
	u64 interval_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cmp_wq_elem);
} cmp_wq_map SEC(".maps");

static int cmp_work_fn(void *map, int *key, void *value)
{
	struct cmp_cfg *cfg = cmp_cfg_lookup();
	u64 usage;

	if (!cfg || !cfg->enabled)
		return 0;

	if (get_cgroup_usage_pages(cfg->monitor_cgroup_id, cfg->page_size,
				   &usage)) {
		cmp_acquire_fails++;
		return 0;
	}

	cmp_protect_now = policy_protect(&cmp_b1_state, usage,
					 bpf_ktime_get_ns(),
					 cfg->drop_rate,
					 cfg->hysteresis_ns);
	cmp_poll_ticks++;

	return 0;
}

static int cmp_timer_cb(void *map, int *key, struct cmp_wq_elem *elem)
{
	bpf_wq_start(&elem->work, 0);
	if (bpf_timer_start(&elem->timer, elem->interval_ns, 0))
		cmp_timer_failures++;

	return 0;
}

/*
 * Seeds both B-arm baselines - one whose prev_ns is 0 would dilute the
 * first sample's fall over the whole uptime - and starts the B1 timer.
 * Both states seed from the same live counter: ctx->usage and
 * bpf_mem_cgroup_usage() are the same page_counter. A failed seed leaves
 * prev_level at 0, which the fall-based policy turns into "first sample
 * carries no evidence", never a spurious trigger. Hook-only arms pass
 * interval_ns = 0 and stop here.
 */
SEC("syscall")
int cmp_prot_init(void)
{
	struct cmp_wq_elem *elem;
	struct cmp_cfg *cfg;
	__u32 key = 0;
	u64 val, now;
	int ret;

	cfg = cmp_cfg_lookup();
	if (!cfg || !cfg->enabled)
		return -1;

	now = bpf_ktime_get_ns();

	if (!get_cgroup_usage_pages(cfg->monitor_cgroup_id, cfg->page_size,
				    &val)) {
		cmp_b1_state.prev_level = val;
		cmp_b2_state.prev_level = val;
	}
	cmp_b1_state.prev_ns = now;
	cmp_b1_state.on_since = 0;
	cmp_b2_state.prev_ns = now;
	cmp_b2_state.on_since = 0;

	if (!cfg->interval_ns)
		return 0;

	elem = bpf_map_lookup_elem(&cmp_wq_map, &key);
	if (!elem)
		return -1;

	ret = bpf_wq_init(&elem->work, &cmp_wq_map, 0);
	if (ret)
		return ret;

	ret = bpf_wq_set_callback(&elem->work, cmp_work_fn, 0);
	if (ret)
		return ret;

	ret = bpf_timer_init(&elem->timer, &cmp_wq_map, CLOCK_MONOTONIC);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&elem->timer, cmp_timer_cb);
	if (ret)
		return ret;

	elem->interval_ns = cfg->interval_ns;

	return bpf_timer_start(&elem->timer, elem->interval_ns, 0);
}

/*
 * Hand-expanded BPF_PROG(): ctx[0] is the member's single argument. The
 * macro is avoided because not every installed bpf_helpers.h has it.
 */
SEC("struct_ops")
__u32 cmp_low_request_poll(unsigned long long *ctx)
{
	struct cmp_cfg *cfg = cmp_cfg_lookup();

	if (!cfg || !cfg->enabled)
		return BPF_MEMCG_PROT_NO_REQUEST;

	cmp_hook_calls++;

	if (!cmp_protect_now)
		return BPF_MEMCG_PROT_NO_REQUEST;

	cmp_note_request();

	return BPF_MEMCG_PROT_REQUEST_USAGE;
}

SEC("struct_ops")
__u32 cmp_low_request_hook(unsigned long long *ctx)
{
	const struct bpf_memcg_prot_ctx *pctx = (const void *)ctx[0];
	struct cmp_cfg *cfg = cmp_cfg_lookup();

	if (!cfg || !cfg->enabled)
		return BPF_MEMCG_PROT_NO_REQUEST;

	cmp_hook_calls++;

	/*
	 * ctx->usage is A's page_counter, read live by the kernel for this
	 * very pass: no kfunc, no acquire route, no rstat flush to wait for.
	 * The fall since the previous pass is the evidence.
	 */
	if (!policy_protect(&cmp_b2_state, pctx->usage, bpf_ktime_get_ns(),
			    cfg->drop_rate, cfg->hysteresis_ns))
		return BPF_MEMCG_PROT_NO_REQUEST;

	cmp_note_request();

	return BPF_MEMCG_PROT_REQUEST_USAGE;
}

SEC("struct_ops")
__u32 cmp_low_request_sanity(unsigned long long *ctx)
{
	struct cmp_cfg *cfg = cmp_cfg_lookup();

	if (!cfg || !cfg->enabled)
		return BPF_MEMCG_PROT_NO_REQUEST;

	cmp_hook_calls++;
	cmp_note_request();

	return BPF_MEMCG_PROT_REQUEST_USAGE;
}

SEC(".struct_ops.link")
struct bpf_memcg_ops cmp_prot_ops_poll = {
	.low_request	= (void *)cmp_low_request_poll,
};

SEC(".struct_ops.link")
struct bpf_memcg_ops cmp_prot_ops_hook = {
	.low_request	= (void *)cmp_low_request_hook,
};

SEC(".struct_ops.link")
struct bpf_memcg_ops cmp_prot_ops_sanity = {
	.low_request	= (void *)cmp_low_request_sanity,
};

char _license[] SEC("license") = "GPL";
