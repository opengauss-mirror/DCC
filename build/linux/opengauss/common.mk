subsysfilename = objfiles.txt

SUBDIROBJS = $(SUBDIRS:%=%/$(subsysfilename))

all: $(subsysfilename)

objfiles.txt: Makefile $(SUBDIROBJS) $(OBJS)
# Don't rebuild the list if only the OBJS have changed.
	$(if $(filter-out $(OBJS),$?),(echo $(addprefix $(subdir)/,$(OBJS)) ) >$@,touch $@)

# make function to expand objfiles.txt contents
expand_subsys = $(foreach file,$(1),$(if $(filter %/objfiles.txt,$(file)),$(addprefix $(DCC_TOP_BUILDDIR)/,$(shell if [ -f $(file) ]; then cat $(file); fi)),$(file)))

# make function to expand objfiles.txt contents
expand_subsys_without_prefix = $(foreach file,$(1),$(if $(filter %/objfiles.txt,$(file)),$($(shell if [ -f $(file) ]; then cat $(file); fi)),$(file)))

# Parallel make trickery
$(SUBDIROBJS): $(SUBDIRS:%=%-recursive) ;

.PHONY: $(SUBDIRS:%=%-recursive)
$(SUBDIRS:%=%-recursive):
	$(MAKE) -C $(subst -recursive,,$@) all

$(call recurse,clean)
clean: clean-local
clean-local:
	rm -f objfiles.txt
