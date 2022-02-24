$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(DCC_TOP_BUILDDIR)/output
CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))

include $(BASE_BUILD_PATH)/common.mk

ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/tools/dcc_encrypt/*c)
OBJS = $(patsubst %.c,%.o,$(ABS_SOURCE))

LDFLAGS += $(addprefix -L,$(COMPONENT_LIB_PATH))
LIBS = -lcbb_static -lsecurec -lssl -lcrypto -lm -ldl -lpthread

.NOTPARALLEL:

all: dcc_encrypt

dcc_encrypt : $(OBJS)
	$(CC) $(CFLAGS) $(call expand_subsys,$(OBJS)) $(LIBS) $(LDFLAGS) -o $@$(X)
	mkdir -p $(DESTDIR)/bin && mv $(DCC_TOP_BUILDDIR)/src/tools/dcc_encrypt/dcc_encrypt $(DESTDIR)/bin

clean:
	rm -f $(DCC_TOP_BUILDDIR)/src/tools/dcc_encrypt/*.o
	rm -f $(DESTDIR)/bin/dcc_encrypt

