#!/bin/bash

echo "install dependencies"

home=$(pwd)

function exec_cmd()
{
	echo "executing $@"
	$@ >/dev/null 2>&1
	local ret=$?

	if [ "${ret}" -ne 0 ]; then
		echo "Failed to execute $@ ret (${ret})"
		exit 1
	fi
}

exec_cmd apt update
exec_cmd apt install -y iproute2

# libwifi-*.so + libeasy.so
cd /opt/dev
rm -fr easy-soc-libs
mkdir -p /usr/include/easy
exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/easy-soc-libs.git
cd easy-soc-libs/libeasy
exec_cmd make CFLAGS+="-I/usr/include/libnl3"
exec_cmd cp -a libeasy*.so* /usr/lib
exec_cmd cp -a easy.h event.h utils.h if_utils.h debug.h hlist.h /usr/include/easy/
cd ../libwifi
exec_cmd make WIFI_TYPE="TEST"
exec_cmd cp wifidefs.h wifiutils.h wifiops.h wifi.h /usr/include
exec_cmd cp -a libwifi*.so* /usr/lib

# wifimngr
cd /opt/dev
rm -fr wifimngr
exec_cmd git clone -b devel https://dev.iopsys.eu/iopsys/wifimngr.git
cd wifimngr
exec_cmd ./gitlab-ci/install-dependencies.sh
exec_cmd ./gitlab-ci/setup.sh
exec_cmd make
exec_cmd cp wifimngr /usr/sbin/

