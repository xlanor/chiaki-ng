#!/bin/bash

cd "`dirname $(readlink -f ${0})`/../.."

docker run \
    -v "`pwd`:/build/chiaki" \
    -w "/build/chiaki" \
    -ti -p 28771:28771 \
    --entrypoint /opt/devkitpro/tools/bin/nxlink \
    docker.io/xlanor/chiaki-ng-switch-builder:latest \
    "$@" -s /build/chiaki/build_switch/switch/chiaki-ng.nro

