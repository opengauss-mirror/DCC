DCC_TOP_BUILDDIR = ..
include $(DCC_TOP_BUILDDIR)/build/linux/opengauss/Makefile.global

SUBDIRS = utils network client tools storage executor server
# Supress parallel build to avoid depencies in the subdirectories.
.NOTPARALLEL:

$(recurse)
