$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../../..))
BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss/
subdir = $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/common \
    $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/kernel \
    $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/protocol
include $(BASE_BUILD_PATH)/Makefile.global
SUBDIRS = $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/common \
    $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/kernel \
    $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/protocol
include $(BASE_BUILD_PATH)/common.mk
CPPFLAGS += $(addprefix -I,$(ZEKERNEL_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CFLAGS += $(GSTOR_OPTIONS)

OBJS = $(SUBDIROBJS)

DESTDIR = $(DCC_TOP_BUILDDIR)/library/zekernel
DEST_INC_DIR = $(DESTDIR)/include
DEST_LIB_DIR = $(DESTDIR)/lib
all: libzekernel.a

libzekernel.a: $(OBJS)
	ar crs $@ $(call expand_subsys, $(OBJS))
	mkdir -p $(DEST_LIB_DIR) && mv $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/libzekernel.a $(DEST_LIB_DIR) 

install:all
clean:
	rm -f $(OBJS) $(DEST_LIB_DIR)/libzekernel.a
distclean: clean
maintainer-clean: distclean