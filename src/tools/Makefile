DCC_TOP_BUILDDIR = ../..
include $(DCC_TOP_BUILDDIR)/build/linux/opengauss/Makefile.global

SUBDIRS = dcc_ctl dcc_encrypt
# Supress parallel build to avoid depencies in the subdirectories.
.NOTPARALLEL:

$(recurse)
