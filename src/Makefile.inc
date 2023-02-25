CP ?= cp -fpPR
INSTALL ?= install
INSTALL_DIR = $(INSTALL) -d -m 755
INSTALL_BIN = $(INSTALL) -m 755
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_CONF = $(INSTALL) -m 600
INSTALL_LIB = $(CP)

ROOTDIR:=$(shell pwd)
INCDIR ?= /usr/include
LIBDIR ?= /usr/lib
BINDIR ?= /usr/sbin

IEEE1905_PLUGINS_DIR:=$(DESTDIR)/$(LIBDIR)/ieee1905

header-files ?= $(wildcard *.h)
library-files ?= $(wildcard *.so*)
bin-files ?=


$(DESTDIR)/$(INCDIR)/%: %
	$(INSTALL_DATA) -D $< $@

$(DESTDIR)/$(LIBDIR)/%: %
	$(INSTALL_DIR) $(DESTDIR)/$(LIBDIR)
	$(INSTALL_LIB) $< $@

$(DESTDIR)/$(BINDIR)/%: %
	$(INSTALL_DIR) $(DESTDIR)/$(BINDIR)
	$(INSTALL_BIN) $< $@

export

install-headers: $(addprefix $(DESTDIR)/$(INCDIR)/,$(header-files))

install-libs: $(addprefix $(DESTDIR)/$(LIBDIR)/,$(library-files))

install-bins: $(addprefix $(DESTDIR)/$(BINDIR)/,$(bin-files))
