# SPDX-License-Identifier: GPL-2.0
CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' \
			       -e 's/aarch64/arm64/' \
			       -e 's/ppc64le/powerpc/' \
			       -e 's/mips.*/mips/' \
			       -e 's/riscv64/riscv/' \
			       -e 's/loongarch64/loongarch/')

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

# Point these at a source build if the distro libbpf is too old, e.g.:
#   make LIBBPF_CFLAGS="-I$(KDIR)/tools/lib/bpf" \
#        LIBBPF_LIBS="-L$(KDIR)/tools/lib/bpf -lbpf -lelf -lz"
LIBBPF_CFLAGS ?=
LIBBPF_LIBS   ?= -lbpf -lelf -lz

# STATIC=1 links libbpf (and libelf/libz) into the binary instead of against
# their shared libraries. Use it when the binary was built against a newer
# libbpf than the one the runtime finds, which otherwise fails with e.g.
#   version `LIBBPF_1.8.0' not found (required by ./memcg_async_reclaim)
# -lzstd is appended automatically: the distro libelf.a is built with zstd
# support but, unlike libelf.so, does not pull libzstd in transitively, so
# install libzstd-dev. The static archives must be reachable, so pair STATIC=1
# with a LIBBPF_LIBS whose -L points at the build that has libbpf.a:
#   make STATIC=1 LIBBPF_CFLAGS="-I$(KDIR)/tools/lib/bpf" \
#                LIBBPF_LIBS="-L$(KDIR)/tools/lib/bpf -lbpf -lelf -lz"
STATIC ?=
ifeq ($(STATIC),1)
LDFLAGS := -Wl,-Bstatic $(LIBBPF_LIBS) -lzstd -Wl,-Bdynamic
else
LDFLAGS := $(LIBBPF_LIBS)
endif

CFLAGS  := -Wall -O2 -g $(LIBBPF_CFLAGS)

TARGET := memcg_async_reclaim

all: $(TARGET)

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

memcg_async_reclaim.bpf.o: memcg_async_reclaim.bpf.c memcg_async_reclaim.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

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
