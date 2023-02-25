CC ?= gcc
EXECS = ieee1905d
CFLAGS +=-I. -D_GNU_SOURCE
CFLAGS += -ggdb3 -Wall -Werror
CFLAGS += -I/usr/include/libnl3

ifeq ($(CC),clang)
	CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
endif

header-files=cmdu.h cmdu_ackq.h 1905_tlvs.h i1905_wsc.h bufutil.h \
	timer_impl.h i1905_extension.h

lib-files=libmidgen.so libieee1905.so
bin-files=ieee1905d


OBJS =  cmdu_input.o  \
	cmdu_output.o \
	config.o \
	policy.o \
	i1905.o \
	i1905_dm.o \
	i1905_al.o \
	i1905_extension.o \
	i1905_ubus.o \
	i1905_netlink.o \
	debug.o \
	cmdufrag.o \
	neigh.o \
	main.o

ifneq (,$(findstring HAS_WIFI,$(CFLAGS)))
OBJS += i1905_wifi.o
endif

LIBOBJS = timer.o \
	  util.o \
	  cmdu.o \
	  cmdu_ackq.o \
	  cryptutil.o \
	  i1905_wsc.o

LIBS = -lubus -lubox -ljson-c -lblobmsg_json -luci -pthread
LIBS += -leasy
LIBS += -rdynamic -ldl
LIBS += -lnl-3 -lnl-genl-3 -lnl-route-3
LIBS += -lssl -lcrypto
LIBSX = $(LIBS)

ifneq (,$(findstring HAS_WIFI,$(CFLAGS)))
LIBSX += -lwifi-7
endif


extmod_subdirs = $(wildcard extensions/*)
extmod_sofile = $(wildcard $(d)/*.so)
extmod_files = $(foreach d, $(extmod_subdirs), $(extmod_sofile))
#LIBS += -rdynamic -ldl
fuzztest_subdirs ?= $(dir $(wildcard tests/fuzz/*/))


.PHONY: all clean docs install tests version.h

all: version libmidgen.so libieee1905.so ieee1905d extmods

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

libieee1905.so: $(LIBOBJS)
	$(CC) -shared -Wl,-soname,libieee1905.so $^ -o $@ $(LIBS) -L. -lmidgen

libmidgen.so: midgen.o
	$(CC) -shared -Wl,-soname,libmidgen.so $^ -o $@ -pthread -lrt


ieee1905d: $(OBJS)
	$(CC) $(LDFLAGS) -L. -o $@ $^ $(LIBSX) -lmidgen -lieee1905


extmods:
	@echo "$(extmod_subdirs)"
	for i in $(extmod_subdirs); do [ -d $$i ] && $(MAKE) -C $$i all; done
	$(MAKE) -C extensions/topology all

tests: fuzz
	#$(MAKE) -C tests all

fuzz:
	for i in $(fuzztest_subdirs); do [ -d $$i ] && $(MAKE) -C $$i all; done


version.h:
	@(\
	[ command -v git > /dev/null 2>&1 ] || { \
		h=$(shell git rev-parse --short=8 HEAD); \
	}; \
	echo "const char *verstring = \"1.0\";" > $@; \
	echo "const char *githash = \"$$h\";" >> $@; \
	)

version: version.h

docs:
	cd docs; doxygen ./Doxyfile
	$(MAKE) -C docs/latex
	cp docs/latex/refman.pdf docs/ieee1905.pdf


-include Makefile.inc

install: install-headers install-libs install-bins
	for i in $(extmod_subdirs); do [ -d $$i ] && $(MAKE) -C $$i install; done

clean:
	rm -f *.o *.so $(EXECS)
	for i in $(extmod_subdirs); do [ -d $$i ] && $(MAKE) -C $$i clean; done
	#$(MAKE) -C tests clean
	for i in $(fuzztest_subdirs); do [ -d $$i ] && $(MAKE) -C $$i clean; done

