#CC = gcc
CFLAGS += -I. -I../.. -O2 -Wall -g -Werror
LDFLAGS += -L.

ifeq ($(CC),clang)
	CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
endif

MAP_PLUGIN = map.so
OBJS = map.o \
       map_module.o

v=$(patsubst -DEASYMESH_VERSION=%,%,$(filter -DEASYMESH_VERSION=%,$(CFLAGS)))
ifeq (4,$(v))
OBJS += aes-siv.o \
	i1905_security.o \
	i1905_eapol.o
endif

UTIL-OBJS = maputil.o \
	policy.o

ifneq (,$(findstring DYNAMIC_CNTLR_SYNC_CONFIG,$(CFLAGS)))
UTIL-OBJS += cntlrsync.o
endif


all: libmaputil.so $(MAP_PLUGIN) tests

tests:
	$(MAKE) -C tests all

libmaputil.so: $(UTIL-OBJS)
	$(CC) -shared -Wl,-soname,libmaputil.so $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

$(MAP_PLUGIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^ -lmaputil

header-files = easymesh.h map_module.h
ifneq (,$(findstring DYNAMIC_CNTLR_SYNC_CONFIG,$(CFLAGS)))
header-files += cntlrsync.h
endif

install:
	$(INSTALL_DIR) $(IEEE1905_PLUGINS_DIR)
	$(INSTALL_DIR) $(DESTDIR)/$(INCDIR)
	$(CP) $(MAP_PLUGIN) $(IEEE1905_PLUGINS_DIR)
	$(CP) libmaputil.so $(DESTDIR)/$(LIBDIR)
	$(INSTALL_DATA) $(header-files) $(DESTDIR)/$(INCDIR)

clean:
	rm -f *.o *.so*

.PHONY: tests clean
