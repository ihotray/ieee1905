#CC = gcc
CFLAGS += -I. -I../.. -O2 -Wall -g -Werror

all: snoop.so

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

snoop.so: snoop.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^

install:
	$(INSTALL_DIR) $(IEEE1905_PLUGINS_DIR)
	$(CP) snoop.so $(IEEE1905_PLUGINS_DIR)

clean:
	rm -f *.o *.so*
