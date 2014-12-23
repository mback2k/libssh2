AUTOMAKE_OPTIONS = foreign nostdinc

SUBDIRS = src tests docs
if BUILD_EXAMPLES
SUBDIRS += example
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libssh2.pc

include_HEADERS =			\
	include/libssh2.h		\
	include/libssh2_publickey.h	\
	include/libssh2_sftp.h

NETWAREFILES =  nw/keepscreen.c \
	nw/nwlib.c \
	nw/GNUmakefile \
	nw/test/GNUmakefile

VMSFILES = vms/libssh2_make_example.dcl vms/libssh2_make_help.dcl	\
vms/libssh2_make_kit.dcl vms/libssh2_make_lib.dcl vms/man2help.c	\
vms/readme.vms vms/libssh2_config.h

WIN32FILES = win32/Makefile.Watcom win32/libssh2.rc

EXTRA_DIST = $(WIN32FILES) buildconf $(NETWAREFILES) get_ver.awk HACKING \
 maketgz NMakefile TODO RELEASE-NOTES libssh2.pc.in $(VMSFILES) config.rpath

ACLOCAL_AMFLAGS = -I m4

.PHONY: ChangeLog
ChangeLog:
	echo "see NEWS" > ./ChangeLog
DISTCLEANFILES = ChangeLog

dist-hook:
	rm -rf $(top_builddir)/tests/log
	find $(distdir) -name "*.dist" -exec rm {} \;
	(distit=`find $(srcdir) -name "*.dist"`; \
	for file in $$distit; do \
	  strip=`echo $$file | sed -e s/^$(srcdir)// -e s/\.dist//`; \
	  cp $$file $(distdir)$$strip; \
	done)

# Code Coverage

init-coverage:
	make clean
	lcov --directory . --zerocounters

COVERAGE_CCOPTS ?= "-g --coverage"
COVERAGE_OUT ?= docs/coverage

build-coverage:
	make CFLAGS=$(COVERAGE_CCOPTS) check
	mkdir -p $(COVERAGE_OUT)
	lcov --directory . --output-file $(COVERAGE_OUT)/$(PACKAGE).info \
		--capture

gen-coverage:
	genhtml --output-directory $(COVERAGE_OUT) \
		$(COVERAGE_OUT)/$(PACKAGE).info \
		--highlight --frames --legend \
		--title "$(PACKAGE_NAME)"

coverage: init-coverage build-coverage gen-coverage
