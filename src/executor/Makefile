$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/executor
DESTDIR = $(DCC_TOP_BUILDDIR)/output

CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))

SUBDIRS = $(DCC_TOP_BUILDDIR)/src/utils
include $(BASE_BUILD_PATH)/common.mk

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/executor/*c $(DCC_TOP_BUILDDIR)/src/utils/*c)
OBJS = $(patsubst %.c,%.o,$(ABS_SOURCE))

.NOTPARALLEL:
all: libdccexecutor.a

libdccexecutor.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -f $(OBJS) libdccexecutor.a

