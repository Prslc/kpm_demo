ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include ./include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir)) -I./include

# Standard KPM flags (see APatch_kpm/nomount/Makefile):
# -mgeneral-regs-only: never use FP/SIMD in kernel context
# -mno-outline-atomics: inline atomics, no __aarch64_* libgcc helpers
# -ffixed-x18: x18 is the arm64 platform register / SCS pointer
# -fno-builtin etc.: no libc-like builtins, stack protector, PIC or unwind tables
CFLAGS += -Wall -O2 -fno-strict-aliasing -fno-PIC \
          -fno-asynchronous-unwind-tables -fno-stack-protector -fno-common \
          -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -fno-builtin

objs := path_hide.o ph_control.o ph_hooks.o ph_config.o ph_registry.o ph_util.o

all: path_hide.kpm

path_hide.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

clean:
	@rm -f *.kpm
	@find . -name "*.o" -delete
