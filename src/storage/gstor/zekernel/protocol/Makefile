$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../../../..))
$(info $(DCC_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/storage/gstor/zekernel/protocol
include $(BASE_BUILD_PATH)/Makefile.global
include $(BASE_BUILD_PATH)/common.mk
CPPFLAGS += $(addprefix -I,$(ZEKERNEL_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CFLAGS += $(GSTOR_OPTIONS)
SOURCE=$(wildcard ./*c)
OBJS = $(patsubst %.c,%.o,$(SOURCE))
all: $(OBJS)
$(OBJS):%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/protocol/$^ -o $@
install:all
clean:
	rm -f $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/protocol/*.o
distclean: clean
maintainer-clean: distclean