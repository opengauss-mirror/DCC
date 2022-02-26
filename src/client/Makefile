$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../..))

BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
DCC_SRC_PATH = $(DCC_TOP_BUILDDIR)/src

include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(DCC_TOP_BUILDDIR)/output

CPPFLAGS += $(addprefix -I,$(COMPONENT_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CPPFLAGS += $(addprefix -I,$(COMM_INC))
CFLAGS += $(DCC_LIB_VERSION_LDFLAG)
$(info $(DCC_LIB_VERSION_LDFLAG))
LDFLAGS += -Wl,-Bsymbolic -rdynamic -fvisibility=hidden -Wl,--exclude-libs,ALL
LDFLAGS += $(addprefix -L,$(COMPONENT_LIB_PATH))
LIBS += -lcbb_static -ldl -lm -lssl -lpthread -lrt -Wl,--whole-archive -lsecurec -Wl,--no-whole-archive

SUBDIRS = $(DCC_SRC_PATH)/utils \
		$(DCC_SRC_PATH)/network
#SOURCE=$(wildcard ./*c)
ABS_SOURCE = $(wildcard $(DCC_TOP_BUILDDIR)/src/client/*c $(DCC_TOP_BUILDDIR)/src/utils/*c $(DCC_TOP_BUILDDIR)/src/network/*c)
OBJS = $(patsubst %.c,%.o,$(ABS_SOURCE)) 
#OBJS = $(SUBDIROBJS) \
		$(OBJS0)

include $(BASE_BUILD_PATH)/common.mk


.NOTPARALLEL:
all: libdcc_driver.so libdccclient.a

libdcc_driver.so: $(OBJS)
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(LIBS) $(ABS_SOURCE) -o libdcc_driver.so
	mkdir -p $(DESTDIR)/lib && mv $(DCC_SRC_PATH)/client/libdcc_driver.so $(DESTDIR)/lib && \
	mkdir -p $(DESTDIR)/include && cp $(DCC_SRC_PATH)/client/interface/clt_interface.h $(DESTDIR)/include

libdccclient.a: $(OBJS)
	ar crs $@ $^ 

clean:
	rm -f $(OBJS)
	rm -f $(DESTDIR)/lib/libdcc_driver.so
	rm -f $(DESTDIR)/include/clt_interface.h
	rm -f libdccclient.a

install:all

uninstall:

distclean: clean

maintainer-clean: distclean
