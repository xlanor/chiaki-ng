#!/bin/bash

cd "`dirname $(readlink -f ${0})`/../.."

docker run --rm \
	-v "`pwd`:/build/chiaki":z \
	-w "/build/chiaki" \
	-it \
	docker.io/xlanor/chiaki-ng-switch-builder:latest \
	/bin/bash -c "scripts/switch/build.sh"

