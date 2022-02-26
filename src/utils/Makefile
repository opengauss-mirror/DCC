$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
include $(BASE_BUILD_PATH)/Makefile.global
#subdir = src/utils
DESTDIR = $(DCC_TOP_BUILDDIR)/output
CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))

include $(BASE_BUILD_PATH)/common.mk
ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/utils/*c $(DCC_TOP_BUILDDIR)/src/utils/parse/*c)
OBJS=$(patsubst %.c,%.o,$(ABS_SOURCE))

.NOTPARALLEL:
all: libdccutils.a 

libdccutils.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -f *.o parse/*.o libdccutils.a
