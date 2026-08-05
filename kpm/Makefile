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

# -O2: matches upstream Linux kernel's own choice (not -O3/-Os).
# -Wall -Wextra: cheap insurance; caught a real kver shadowing bug via
#   -Wshadow during review.
# -fno-strict-aliasing: this module reinterprets a raw uint64_t hook-arg
#   slot as char**/uint32_t* (see after_sid_to_context) -- exactly what
#   strict-aliasing optimizations may miscompile. Kernel is built the same
#   way for the same reason.
# -fno-builtin: without it, GCC can substitute its own memcpy/strcmp/...
#   instead of calling KernelPatch's kfunc-backed versions.
# -fno-stack-protector: no stack-smashing checks in a freestanding KPM;
#   otherwise risks a __stack_chk_fail undefined-symbol failure at load.
# -fno-common: standard kernel-module hygiene for globals.
# -fno-asynchronous-unwind-tables -fno-unwind-tables: drops .eh_frame
#   sections meaningless in a relocatable KPM object.
# -fno-pic -fno-pie: REQUIRED, not a precaution -- without these, real
#   aarch64 GCC emits GOT-relative relocations KernelPatch's loader
#   rejects at boot. See DEBUGGING.md Bug 1 for the full story.
CFLAGS ?= -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -O2 \
          -fno-strict-aliasing -fno-builtin -fno-stack-protector -fno-common \
          -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pic -fno-pie

objs := auditpatch.o

all: $(MODULE_NAME).kpm

$(MODULE_NAME).kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
