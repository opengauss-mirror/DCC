# DCC_TOP_BUILDDIR = ../..
$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/storage/gstor

DESTDIR = $(DCC_TOP_BUILDDIR)/output

CPPFLAGS += $(addprefix -I,$(ZEKERNEL_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CFLAGS += $(GSTOR_OPTIONS)

SUBDIRS =   $(DCC_SRC_PATH)/storage/gstor/zekernel

include $(BASE_BUILD_PATH)/common.mk

SOURCE=$(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SOURCE))
ABS_SOURCE=$(patsubst %.o,$(DCC_SRC_PATH)/storage/gstor/%.c,$(OBJS))

LDFLAGS += -L$(DCC_TOP_BUILDDIR)/library/zekernel/lib
LIBS += -Wl,-Bsymbolic -rdynamic -fvisibility=hidden -Wl,--exclude-libs,ALL -lzekernel -lz -llz4 -lzstd -lssl -lcrypto -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive  -lm -lpthread -lrt
.NOTPARALLEL:
all: libgstor.so

libgstor.so:
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(ABS_SOURCE) $(LIBS) -o libgstor.so
	mkdir -p $(DESTDIR)/lib && mv libgstor.so $(DESTDIR)/lib

clean:
	rm -f $(OBJS) $(DESTDIR)/lib/libgstor.so

