#!/bin/sh
# Builds a docker image

usage() {
	echo "Usage: $0 [-i image-name] [- t image-tag] [-f Dockerfile] [-n Docker-network] [-h usage]"
	exit 0
}

while getopts "u:a:f:n:h" OPTIONS; do
    case "${OPTIONS}" in
        i) img=${OPTARG} ;;
        t) tag=${OPTARG} ;;
        f) filename=${OPTARG} ;;
        n) network=${OPTARG} ;;
	h) usage ;;
    esac
done

filename=${filename:-Dockerfile}
img=${img:-i1905-image}
tag=${tag:-latest}
network=${network:-multiap-bridge-network}

docker build -f ${filename} -t ${img}:${tag} .

echo "Create multiap bridge network ..."
docker network create -d bridge \
	--subnet=192.168.0.0/24 \
	--opt "com.docker.network.bridge.name"="br-multiap" \
	${network}
