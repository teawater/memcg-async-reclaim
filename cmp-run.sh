#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Interleaved runner for the three-arm memory.low request comparison
# (memcg-async-reclaim-memcg_ext-v2-plan.md sections 3, 6, 7).
#
# Per round: a sanity gate (the protection chain must demonstrably work),
# then the three arms in rotating order, with cache drops between runs.
# Every run appends one row to the CSV; raw rows are the publication data.
#
# Requirements:
#   - root, cgroup v2 unified hierarchy
#   - the kernel booted with psi=1 (CONFIG_PSI_DEFAULT_DISABLED=y kernels):
#     the PSI columns are report data and the poll rows need memory.pressure;
#     without it the tool now fails loudly instead of logging silent zeros
#   - the kernel under test booted with memcg_ext v2 (bpf_memcg_ops with
#     low_request), and vmlinux.h regenerated from it (make clean && make)
#   - kernel.bpf_stats_enabled is toggled by the tool itself per run
#
# Calibration (plan P0): all three arms run the same policy on the same
# counter - A's memory.current, the live page_counter - and trigger on its
# fall rate in pages per second (reclaim uncharges A synchronously, so a
# dropping usage is "A is being stolen from"; pgsteal proved unobservable
# inside the hook - it only advances in rstat-flush steps - and workingset
# refaults proved blind under B's shrinker churn; both stay outcome/display
# columns). The arms differ only in sampling (U: pread from a timer/poll
# loop; B1: bpf_mem_cgroup_usage() on a wq tick; B2: ctx->usage on every
# protection pass). The threshold is a RATE, so it stays arm-independent
# despite the ~10x sampling-frequency spread. Calibrate THRESHOLD and the
# pacing knobs from a first sanity run so that every arm engages protection
# promptly under the same burst, record the values used in the results, and
# keep them identical across every round.

set -u

TOOL=${TOOL:-./memcg_async_reclaim}
ROUNDS=${ROUNDS:-15}
DURATION=${DURATION:-30}
RAMP=${RAMP:-5}
# One timestamped run directory holds everything (CSV, per-run logs,
# environment, void list), so a run is copied between machines as a unit.
RUNDIR=${RUNDIR:-run-$(date +%Y%m%d-%H%M%S)}
CSV=${CSV:-$RUNDIR/results.csv}
LOGDIR=${LOGDIR:-$RUNDIR/logs}

# Topology and policy knobs (plan section 5 defaults). Keep identical
# across arms and rounds; only --impl/--trigger/--interval vary.
BUDGET=${BUDGET:-64M}
TMAX=${TMAX:-160M}
FILLER=${FILLER:-112M}   # keep A+B under TMAX so the ramp runs reclaim-free
BURST=${BURST:-64M}
AFILE=${AFILE:-32M}
AGENT_MIN=${AGENT_MIN:-8M}
THRESHOLD=${THRESHOLD:-12800}        # A memory.current fall, pages/sec (all arms)
HYSTERESIS=${HYSTERESIS:-50}         # ms
READ_CYCLE_MS=${READ_CYCLE_MS:-500}  # A re-read pacing: pages go cold between passes
FILLER_SLEEP_MS=${FILLER_SLEEP_MS:-500}  # B rewrite cadence: the renewable cold-page flow
INTERVAL=${INTERVAL:-5}              # ms, B1 tick and U timer tick
PSI_US=${PSI_US:-10000}              # U poll trigger: stall us per 1s
U_TRIGGER=${U_TRIGGER:-timer}        # the U arm's trigger in the 3-arm phase
UCURVE_ROUNDS=${UCURVE_ROUNDS:-5}    # reps per phase-2 curve point (median)

COMMON="--duration $DURATION --ramp $RAMP --budget $BUDGET --tmax $TMAX \
--filler $FILLER --burst $BURST --file-size $AFILE --agent-min $AGENT_MIN \
--threshold $THRESHOLD --hysteresis $HYSTERESIS \
--read-cycle $READ_CYCLE_MS --filler-sleep $FILLER_SLEEP_MS \
--csv $CSV"

mkdir -p "$LOGDIR"

if [ "$(id -u)" != 0 ]; then
	echo "must run as root" >&2
	exit 1
fi

# A missing /proc/pressure means every PSI column would silently read 0 and
# the poll rows would die in the agent - refuse to produce such a dataset.
if [ ! -e /proc/pressure/memory ]; then
	echo "ERROR: PSI is disabled; reboot with psi=1 on the kernel cmdline" >&2
	exit 1
fi

record_swap() {
	{
		echo "kernel: $(uname -r)"
		echo "swap:"
		cat /proc/swaps
		echo "meminfo: $(grep -E '^(MemTotal|MemFree|SwapTotal)' /proc/meminfo | tr '\n' ' ')"
	} >> "$LOGDIR/environment.txt"
}

drop_caches() {
	sync
	echo 3 > /proc/sys/vm/drop_caches
	sleep 2
}

run_arm() {
	local impl=$1 trigger=$2 interval=$3 tag=$4
	local log="$LOGDIR/round$(printf '%02d' "$ROUND")-$tag.log"

	echo "=== round $ROUND: $tag (impl=$impl trigger=$trigger interval=${interval}ms) ==="
	drop_caches
	# shellcheck disable=SC2086
	$TOOL cmp --impl "$impl" --trigger "$trigger" --interval "$interval" \
		--psi-us "$PSI_US" $COMMON 2>&1 | tee "$log"
	# A void round (protection never engaged) poisons the statistics;
	# surface it loudly rather than letting it hide in the CSV.  The two
	# curve endpoints are the exception: their voids ARE the data point
	# (100ms saturates; poll never fires because A does not stall).
	if grep -q "ROUND VOID" "$log"; then
		local note=""
		case $tag in
		ucurve-timer-100ms*|ucurve-poll*)
			note=" (expected curve endpoint, not a protocol failure)" ;;
		esac
		echo "WARNING: round $ROUND arm $tag VOID (trigger not reached)$note" \
			| tee -a "$LOGDIR/void-rounds.txt"
	fi
}

sanity_gate() {
	local log="$LOGDIR/round$(printf '%02d' "$ROUND")-sanity.log"

	echo "=== round $ROUND: sanity gate ==="
	drop_caches
	# shellcheck disable=SC2086
	$TOOL cmp --impl sanity --duration 10 --ramp 3 --budget $BUDGET \
		--tmax $TMAX --filler $FILLER --burst $BURST --file-size $AFILE \
		--agent-min $AGENT_MIN --threshold $THRESHOLD \
		--hysteresis $HYSTERESIS \
		--read-cycle $READ_CYCLE_MS --filler-sleep $FILLER_SLEEP_MS \
		2>&1 | tee "$log"
	if ! grep -q "sanity: PASS" "$log"; then
		echo "ERROR: sanity gate FAILED in round $ROUND - the protection" \
			"chain did not demonstrably work; aborting." | tee -a "$LOGDIR/void-rounds.txt"
		exit 1
	fi
}

record_swap

# Phase 1: the three arms, interleaved with rotating order so that no arm
# systematically runs on a colder/warmer machine (plan section 7).
ARMS=(user bpf-poll bpf-hook)
for ROUND in $(seq "$ROUNDS"); do
	sanity_gate
	start=$(( (ROUND - 1) % 3 ))
	for i in 0 1 2; do
		arm=${ARMS[$(( (start + i) % 3 ))]}
		case $arm in
		user)     run_arm user "$U_TRIGGER" "$INTERVAL" "user-$U_TRIGGER" ;;
		bpf-poll) run_arm bpf-poll timer "$INTERVAL" bpf-poll ;;
		bpf-hook) run_arm bpf-hook timer 0 bpf-hook ;;
		esac
	done
done

# Phase 2: the U arm's latency/CPU curve - the anti-strawman sweep (plan
# section 2.2): if B2's advantage only appears against a slow agent, these
# rows show where the userspace arm saturates and what it costs to get there.
# Each point repeats UCURVE_ROUNDS times: a single run per interval proved
# too noisy to order the points (episode luck once put 20ms worse than
# 100ms), so the publication statistic is the per-point median.
if [ "${U_CURVE:-1}" = 1 ]; then
	ROUND=0
	for iv in 1 5 20 100; do
		for rep in $(seq "${UCURVE_ROUNDS}"); do
			ROUND=$((ROUND + 1))
			run_arm user timer "$iv" "ucurve-timer-${iv}ms-rep${rep}"
		done
	done
	for rep in $(seq "${UCURVE_ROUNDS}"); do
		ROUND=$((ROUND + 1))
		run_arm user poll 0 "ucurve-poll-${PSI_US}us-rep${rep}"
	done
fi

echo
echo "done. run dir: $RUNDIR/ (rows: $CSV, logs: $LOGDIR/) - copy it as a unit"
echo "void rounds: $( [ -f "$LOGDIR/void-rounds.txt" ] && wc -l < "$LOGDIR/void-rounds.txt" || echo 0 )"
