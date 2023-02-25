
CC ?= gcc
CFLAGS += -g -Wall -I../../../ -I../../.. -I../../../extensions/map
LDFLAGS += -L../../../ -L../.. -L../../../extensions/map

ifeq ($(CC),clang)
	CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
endif


LIBS = -lubox -lubus -ljson-c -lblobmsg_json -luci -leasy
LIBS += -lmaputil -lieee1905 -lmidgen
#LIBS += -lnl-3 -lnl-route-3


all: mapclient1 mapclient2

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

mapclient1: mapclient1.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

mapclient2: mapclient2.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm *.o mapclient1 mapclient2

.PHONY: clean
