#CC = gcc
CFLAGS += -I. -I../.. -O2 -Wall -g -Werror

all: topology.so

%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

topology.so: topology.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^

install:
	$(INSTALL_DIR) $(IEEE1905_PLUGINS_DIR)
	$(CP) topology.so $(IEEE1905_PLUGINS_DIR)

clean:
	rm -f *.o *.so*
