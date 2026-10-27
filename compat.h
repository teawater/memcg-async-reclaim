/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COMPAT_H
#define __COMPAT_H

/*
 * Minimal stand-ins for the <linux/compiler.h> accessors, so that the build
 * depends on nothing but libc, libbpf and a generated vmlinux.h.
 */

#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) (*(volatile typeof(x) *)&(x) = (val))
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

/* <linux/kernel.h> has this, but pulling that in would drag in the rest. */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#endif /* __COMPAT_H */
