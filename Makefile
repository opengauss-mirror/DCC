DCC_TOP_BUILDDIR = $(shell pwd)
include $(DCC_TOP_BUILDDIR)/build/linux/opengauss/Makefile.global

SUBDIRS = src

# Supress parallel build to avoid depencies in the subdirectories.
.NOTPARALLEL:

$(recurse)
