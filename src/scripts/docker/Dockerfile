FROM ubuntu:20.04 AS builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
		apt-utils build-essential git cmake pkg-config \
		openssl libssl-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev \
		iptables clang libclang-dev vim valgrind \
		&& rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN echo "Start building packages..."

# using clang
RUN ln -sf /usr/bin/clang /usr/bin/cc

# Install JSON-C
RUN \
	git clone https://github.com/json-c/json-c.git && \
	cd json-c && \
	git checkout 9021cdcdd01fc9dbcbe1f06391848c2ac915212f && \
	cmake -DCMAKE_INSTALL_PREFIX=/usr . && \
	make && \
	make install

# ubox
RUN \
      git clone  git://git.openwrt.org/project/libubox.git && \
      cd libubox && mkdir build && cd build && \
      git checkout b14c4688612c05c78ce984d7bde633bce8703b1e && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF .. && \
      make -j2 && \
      make install

# uci
RUN \
	git clone git://git.openwrt.org/project/uci.git && \
	cd uci && \
	git checkout 52bbc99f69ea6f67b6fe264f424dac91bde5016c && \
	cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF . && \
	make -j2 && \
	make install

# ubus
RUN \
	git clone https://git.openwrt.org/project/ubus.git && \
	cd ubus && \
	git checkout 4fc532c8a55ba8217ad67d7fd47c5eb9a8aba044 && \
	cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF . && \
	make -j2 && \
	make install

# libeasy, libwifi (optional)
RUN \
	git clone https://dev.iopsys.eu/iopsys/easy-soc-libs.git && \
	cd easy-soc-libs && \
	git checkout b6baf5a2c1213230651912bd9141f1cee02e500a && \
	PLATFORM="TEST" CFLAGS="-I/usr/include/libnl3 -DIOPSYS_TEST" make subdirs="libeasy libwifi" && \
	PLATFORM="TEST" make subdirs="libeasy libwifi" install

# wifimngr
RUN \
	git clone https://dev.iopsys.eu/iopsys/wifimngr.git && \
	cd wifimngr && \
	git checkout af1c9ae51544532bc535814de63f9a55d2388792 && \
	make && \
	make install

# ieee1905
RUN \
	git clone https://dev.iopsys.eu/iopsys/ieee1905.git && \
	cd ieee1905/src && \
	git checkout 247ca3548c7da738c900fb0d63fb3e4e893ea78e && \
	CC=clang make EXTRA_CFLAGS="-DHAS_WIFI" && \
	CC=clang make install

RUN echo "Done building packages. Now copying files and init scripts"

#ieee1905 test image
FROM builder AS i1905test
RUN rm -rf /tmp/*
WORKDIR /root/

RUN mkdir -p /etc/config
COPY ./files/* /etc/config/

COPY multiap.sh /root/multiap.sh
ENTRYPOINT ["/root/multiap.sh"]
CMD ["--multiap_mode","full","--alid","cc:cc:cc:11:22:33"]
