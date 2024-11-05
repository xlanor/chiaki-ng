#!/bin/bash

set -xveo pipefail

arg1=$1
build="./build"
if [ "$arg1" != "linux" ]; then
	toolchain="cmake/switch.cmake"
	build="./build_switch"
fi

SCRIPTDIR=$(dirname "$0")
BASEDIR=$(realpath "${SCRIPTDIR}/../../")

build_chiaki (){
	pushd "${BASEDIR}"
		#rm -rf ./build

		# purge leftover proto/nanopb_pb2.py which may have been created with another protobuf version
		rm -fv third-party/nanopb/generator/proto/nanopb_pb2.py

		cmake -B "${build}" \
			-GNinja \
			-DCMAKE_TOOLCHAIN_FILE=${toolchain} \
			-DCHIAKI_ENABLE_TESTS=OFF \
			-DCHIAKI_ENABLE_CLI=OFF \
			-DCHIAKI_ENABLE_GUI=OFF \
			-DCHIAKI_ENABLE_ANDROID=OFF \
			-DCHIAKI_ENABLE_BOREALIS=ON \
			-DCHIAKI_LIB_ENABLE_MBEDTLS=ON \
			-DCHIAKI_ENABLE_STEAMDECK_NATIVE=OFF\
			-DCHIAKI_ENABLE_STEAM_SHORTCUT=OFF \
			-DCMAKE_FIND_DEBUG_MODE=OFF \
			-DOPENSSL_INCLUDE_DIR="/usr/include/openssl" \ 
			-DOPENSSL_SSL_LIBRARY=/usr/lib/libssl.so.3 \
			-DOPENSSL_CRYPTO_LIBRARY=/usr/lib/libcrypto.so.3
			# -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
			# -DCMAKE_FIND_DEBUG_MODE=ON

		ninja -C "${build}"
	popd
}

build_chiaki

