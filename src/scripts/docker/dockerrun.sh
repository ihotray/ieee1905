#!/bin/sh

# Example usage:
# ./dockerrun.sh my-container [ --multiap_mode full --alid 00:10:20:aa:bb:cc ]
#

name=${1:-i1905-node1}
shift

echo "container name = '$name'"

[ "$1" == "" ] && {
	echo "no extra CMD args provided ..."
} || {
	echo $@
}


# check if our desired network exists; else create
#docker network ls --filter driver=bridge --filter name=multiap-bridge-network

docker run --privileged -dit --rm --name ${name} \
	--net=multiap-bridge-network i1905-image \
	$@

