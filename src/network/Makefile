$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src
include $(BASE_BUILD_PATH)/Makefile.global
DESTDIR = $(DCC_TOP_BUILDDIR)/output

CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))
SUBDIRS = $(DCC_SRC_PATH)/utils
include $(BASE_BUILD_PATH)/common.mk

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/network/*c)
OBJS=$(patsubst %.c,%.o,$(ABS_SOURCE))

.NOTPARALLEL:
all: libdccnetwork.a

libdccnetwork.a: $(OBJS)
	ar crs $@ $(call expand_subsys_without_prefix, $(OBJS))

clean:
	rm -f *.o libdccnetwork.a
