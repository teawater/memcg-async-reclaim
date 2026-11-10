# SPDX-License-Identifier: GPL-2.0
CLANG   ?= clang
CC      ?= gcc

# Build everything from a specific kernel tree:
#   make KDIR=/path/to/linux
# vmlinux.h is taken from that tree's vmlinux, and the libbpf
# headers/library plus bpftool (if built) from its tools/ directory
# instead of the system installs; the tree's tools/lib/bpf must be
# built beforehand. VMLINUX_BTF, BPFTOOL and LIBBPF_CFLAGS/LIBBPF_LIBS
# still override the individual pieces.
ifdef KDIR
VMLINUX_BTF   ?= $(KDIR)/vmlinux
LIBBPF_CFLAGS ?= -I$(KDIR)/tools/lib
LIBBPF_LIBS   ?= -L$(KDIR)/tools/lib/bpf -Wl,-rpath,$(KDIR)/tools/lib/bpf \
		 -lbpf -lelf -lz
ifneq ($(wildcard $(KDIR)/tools/bpf/bpftool/bpftool),)
BPFTOOL ?= $(KDIR)/tools/bpf/bpftool/bpftool
endif
endif

VMLINUX_BTF   ?= /sys/kernel/btf/vmlinux
LIBBPF_CFLAGS ?=
LIBBPF_LIBS   ?= -lbpf -lelf -lz
BPFTOOL       ?= bpftool

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' \
			       -e 's/aarch64/arm64/' \
			       -e 's/ppc64le/powerpc/' \
			       -e 's/mips.*/mips/' \
			       -e 's/riscv64/riscv/' \
			       -e 's/loongarch64/loongarch/')

CFLAGS  := -Wall -O2 -g $(LIBBPF_CFLAGS)
LDFLAGS := $(LIBBPF_LIBS)

# STATIC=1 links the binary fully static, so it runs on hosts without the
# matching shared libraries (e.g. a test VM). Needs libbpf.a (with KDIR the
# kernel tree's), libelf.a, libz.a and libc.a installed, plus libzstd-dev:
# distro libelf.a is built with zstd compression support, which dynamic
# linking resolves automatically but static linking needs -lzstd for.
ifeq ($(STATIC),1)
LDFLAGS += -static -lzstd
endif

TARGET := memcg_async_reclaim

all: $(TARGET)

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

memcg_async_reclaim.bpf.o: memcg_async_reclaim.bpf.c memcg_async_reclaim.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS) -c $< -o $@

memcg_async_reclaim.skel.h: memcg_async_reclaim.bpf.o
	$(BPFTOOL) gen skeleton $< name memcg_async_reclaim > $@

memcg_async_reclaim_user.o: memcg_async_reclaim_user.c memcg_async_reclaim.skel.h \
			    memcg_async_reclaim.h cgroup_helpers.h compat.h
	$(CC) $(CFLAGS) -c $< -o $@

cgroup_helpers.o: cgroup_helpers.c cgroup_helpers.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): memcg_async_reclaim_user.o cgroup_helpers.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o memcg_async_reclaim.skel.h vmlinux.h

.PHONY: all clean
