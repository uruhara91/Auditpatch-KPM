ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set, e.g. export TARGET_COMPILE=aarch64-none-elf-)
endif

# KP_DIR must point at a checkout of https://github.com/bmax121/KernelPatch
# (only the header-only kernel/ tree is needed, no build of KernelPatch
# itself is required). Defaults to a sibling checkout for local dev.
ifndef KP_DIR
    KP_DIR = ../../KernelPatch
endif

CC := $(TARGET_COMPILE)gcc
LD := $(TARGET_COMPILE)ld

MODULE_NAME := auditpatch

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# -O2: matches upstream Linux kernel's own choice, not -O3/-Os. -O3's more
#   aggressive inlining/vectorization is explicitly avoided by mainline
#   kernel code, and -Os has a history of worse/buggier codegen on kernel
#   code with some GCC versions; -O2 is the well-trodden path for this kind
#   of freestanding, hook-heavy C.
# -Wall -Wextra: catches real bugs at zero runtime cost (e.g. this project's
#   Makefile/source caught a genuine `kver` parameter-shadows-global issue
#   during review purely from -Wshadow; -Wextra is cheap insurance for the
#   next change).
# -fno-strict-aliasing: this module repeatedly reinterprets a raw uint64_t
#   hook-argument slot as `char **`/`uint32_t *` (see after_sid_to_context
#   in auditpatch.c) -- exactly the pattern strict-aliasing optimizations
#   are allowed to miscompile. The kernel itself is built the same way for
#   the same reason.
# -fno-builtin: without this, GCC's builtin recognition of standard names
#   (memcpy/strcmp/strncmp/...) can substitute its own expansion instead of
#   actually calling KernelPatch's kfunc-backed implementations of those
#   same names -- silently bypassing the indirection this environment
#   relies on. Independently confirmed necessary by another real KPM
#   project (Admirepowered/selinux_hook's Makefile disables the same
#   builtins), not just a defensive guess here.
# -fno-stack-protector: makes the "no stack-smashing checks in a freestanding
#   KPM" assumption explicit rather than relying on the aarch64-none-elf
#   toolchain's own default (which could differ across toolchain versions);
#   the alternative is a __stack_chk_fail undefined-symbol failure at KPM
#   load time.
# -fno-common: standard kernel-module hygiene for global variable placement.
#   Every global in this module already has an initializer, so this is a
#   no-op today, but it's a cheap guard against a future uninitialized
#   global becoming a tentative/COMMON symbol.
# -fno-asynchronous-unwind-tables -fno-unwind-tables: drops .eh_frame /
#   .eh_frame_hdr sections that have no meaning in a relocatable KPM object
#   (nothing unwinds through kernel code this way) -- smaller .kpm, and one
#   less category of section for the KPM loader to have to not care about.
#
# Deliberately NOT added, despite being tempting:
# -O3 / -Os: see -O2 note above.
# -ffreestanding / -fPIC / -fno-PIC: the upstream KernelPatch demo KPMs
#   (kpms/demo-hello, kpms/demo-syscallhook) build and are confirmed to
#   load correctly *without* setting any of these, and this project has no
#   way to test a real .kpm against a real kernel to verify a deviation
#   from that proven baseline is safe. If you can test on real hardware and
#   confirm one of these helps (or is needed), that's a much stronger basis
#   for adding it than reasoning about it in the abstract.
CFLAGS ?= -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O2 \
          -fno-strict-aliasing -fno-builtin -fno-stack-protector -fno-common \
          -fno-asynchronous-unwind-tables -fno-unwind-tables

objs := auditpatch.o

all: $(MODULE_NAME).kpm

$(MODULE_NAME).kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
