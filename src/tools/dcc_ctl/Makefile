$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(DCC_TOP_BUILDDIR)/output
CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))

SUBDIRS = $(DCC_SRC_PATH)/utils \
	$(DCC_SRC_PATH)/network \
	$(DCC_SRC_PATH)/client

include $(BASE_BUILD_PATH)/common.mk

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/tools/dcc_ctl/*c) \
	$(DCC_TOP_BUILDDIR)/src/client/libdccclient.a \
	$(DCC_TOP_BUILDDIR)/src/utils/libdccutils.a \
	$(DCC_TOP_BUILDDIR)/src/network/libdccnetwork.a
OBJS = $(patsubst %.c,%.o,$(ABS_SOURCE)) 

LDFLAGS += $(addprefix -L,$(COMPONENT_LIB_PATH))
LIBS = -lcbb_static -lcjson -lsecurec -lssl -lcrypto -lm -ldl -lpthread

.NOTPARALLEL:

all: dcc_ctl

dcc_ctl : $(OBJS)
	$(CC) $(CFLAGS) $(call expand_subsys,$(OBJS)) $(LIBS) $(LDFLAGS) -o $@$(X)
	mkdir -p $(DESTDIR)/bin && mv $(DCC_TOP_BUILDDIR)/src/tools/dcc_ctl/dcc_ctl $(DESTDIR)/bin

clean:
	rm -f $(OBJS)
	rm -f $(DESTDIR)/bin/dcc_ctl
