$(eval DCC_TOP_BUILDDIR := $(abspath $(CURDIR)/../../../../..))
$(info $(DCC_TOP_BUILDDIR))
BASE_BUILD_PATH = $(DCC_TOP_BUILDDIR)/build/linux/opengauss
subdir = src/storage/gstor/zekernel/kernel
include $(BASE_BUILD_PATH)/Makefile.global
include $(BASE_BUILD_PATH)/common.mk
CPPFLAGS += $(addprefix -I,$(ZEKERNEL_INC))
CPPFLAGS += $(addprefix -I,$(3RD_INC))
CFLAGS += $(GSTOR_OPTIONS)
SOURCE=$(wildcard ./*c ./backup/*c ./buffer/*c ./catalog/*c ./common/*c ./daemon/*c ./flashback/*c ./index/*c \
./lob/*c ./persist/*c ./replication/*c ./sequence/*c ./statistics/*c ./table/*c ./tablespace/*c ./xact/*c)
OBJS = $(patsubst %.c,%.o,$(SOURCE))
all: $(OBJS)
$(OBJS):%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/kernel/$^ -o $@
install:all
clean:
	rm -f $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/kernel/*.o $(DCC_TOP_BUILDDIR)/src/storage/gstor/zekernel/kernel/*/*.o
distclean: clean
maintainer-clean: distclean

