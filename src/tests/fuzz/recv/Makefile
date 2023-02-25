CC = clang
CFLAGS ?= -O2 -Wall -g -Werror -I../../..
LDFLAGS ?= -L../../..

FUZZ_CFLAGS = -fsanitize=fuzzer,address
FUZZ_LDFLAGS = -fsanitize=fuzzer,address

CFLAGS += $(FUZZ_CFLAGS)
LDFLAGS += $(FUZZ_LDFLAGS)

ifeq ($(CC),clang)
	CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
endif


LIBS = -lubus -lubox -ljson-c -lblobmsg_json
LIBS += -leasy -lieee1905

.PHONY: all rxcmdu clean

all: rxcmdu

rxcmdu: rxcmdu.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install:
	$(INSTALL_DIR) $(DESTDIR)/$(BINDIR)
	$(CP) rxcmdu $(DESTDIR)/$(BINDIR)

clean:
	rm -f *.o rxcmdu
