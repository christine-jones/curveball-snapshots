
USE_STATIC_LIBS=1

include manifest.mn

include $(CORE_DEPTH)/coreconf/config.mk

# We need to put this early, because it references symbols in
# in several of the other libraries.
#
EXTRA_LIBS += $(DIST)/lib/$(LIB_PREFIX)nsscb.$(LIB_SUFFIX)

include ../platlibs.mk

ifdef USE_SYSTEM_ZLIB
OS_LIBS += $(ZLIB_LIBS)
else
EXTRA_LIBS += $(ZLIB_LIBS)
endif

include $(CORE_DEPTH)/coreconf/rules.mk

include ../platrules.mk

# just so we can use the same "compile" directive to EMACS as when building the libraries.
nss_build_all: $(PROGRAM) 
