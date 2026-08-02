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

CFLAGS ?= -Wall -Wno-unused-function

objs := auditpatch.o

all: $(MODULE_NAME).kpm

$(MODULE_NAME).kpm: $(objs)
	$(CC) -r -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
