$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/storage
CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))
DESTDIR = $(DCC_TOP_BUILDDIR)/output

SUBDIRS = gstor
include $(BASE_BUILD_PATH)/common.mk

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/storage/*c)
OBJS=$(patsubst %.c,%.o,$(ABS_SOURCE))

.NOTPARALLEL:
all: libdccstorage.a

libdccstorage.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -f *.o libdccstorage.a 

