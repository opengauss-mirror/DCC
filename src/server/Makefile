# DCC_TOP_BUILDDIR = ../..
$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/server

DESTDIR = $(DCC_TOP_BUILDDIR)/output

CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))
CFLAGS += $(DCC_LIB_VERSION_LDFLAG)

SUBDIRS = $(DCC_SRC_PATH)/utils \
			$(DCC_SRC_PATH)/storage \
			$(DCC_SRC_PATH)/network \
			$(DCC_SRC_PATH)/executor

include $(BASE_BUILD_PATH)/common.mk

OBJS = server.o srv_agent.o srv_api.o srv_cmd_exe.o srv_config.o srv_instance.o \
	srv_logger.o srv_lsnr.o srv_param.o srv_reactor.o srv_session.o srv_watch.o \
	$(DCC_TOP_BUILDDIR)/src/utils/libdccutils.a \
	$(DCC_TOP_BUILDDIR)/src/network/libdccnetwork.a \
	$(DCC_TOP_BUILDDIR)/src/storage/libdccstorage.a \
	$(DCC_TOP_BUILDDIR)/src/executor/libdccexecutor.a

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/server/*c) \
	$(DCC_TOP_BUILDDIR)/src/utils/libdccutils.a \
	$(DCC_TOP_BUILDDIR)/src/network/libdccnetwork.a \
	$(DCC_TOP_BUILDDIR)/src/storage/libdccstorage.a \
	$(DCC_TOP_BUILDDIR)/src/executor/libdccexecutor.a
OBJS=$(patsubst %.c,%.o,$(ABS_SOURCE))
LDFLAGS += -L$(DCC_TOP_BUILDDIR)/output/lib
LDFLAGS += $(addprefix -L,$(COMPONENT_LIB_PATH))
LIBS = -Wl,-Bsymbolic -rdynamic -fvisibility=hidden -Wl,--exclude-libs,ALL -lcbb_static -ldcf  -lgstor -lz -llz4 -lzstd -lcjson -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive -lssl -lcrypto -lm -ldl -lpthread

.NOTPARALLEL:
all:  libdcc.so dcc_server

libdcc.so:
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(ABS_SOURCE) $(LIBS) -o libdcc.so
	mkdir -p $(DESTDIR)/lib && mv $(DCC_TOP_BUILDDIR)/src/server/libdcc.so $(DESTDIR)/lib/libdcc.so &&\
	mkdir -p $(DESTDIR)/include && cp $(DCC_TOP_BUILDDIR)/src/interface/dcc_interface.h $(DESTDIR)/include

dcc_server : $(OBJS)
	$(CC) -fPIE $(CFLAGS) $(CPPFLAGS) $(call expand_subsys,$(OBJS)) $(LIBS) $(LDFLAGS) -o dcc_server
	mkdir -p $(DESTDIR)/bin && mv $(DCC_TOP_BUILDDIR)/src/server/dcc_server $(DESTDIR)/bin

clean:
	rm -f $(OBJS) $(DESTDIR)/lib/libdcc.so $(DESTDIR)/bin/dcc_server $(DESTDIR)/include/dcc_interface.h

