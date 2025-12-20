
add_library(munit "${CMAKE_CURRENT_SOURCE_DIR}/munit/munit.c")
target_include_directories(munit PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/munit")

add_executable(chiaki-unit
		main.c
		http.c
		rpcrypt.c
		gkcrypt.c
		takion.c
		seqnum.c
		keystate.c
		reorderqueue.c
		fec.c
		test_log.c
		test_log.h
		bitstream.c
		regist.c)

target_link_libraries(chiaki-unit chiaki-lib munit)

add_test(unit chiaki-unit)

# libnx crypto backend test - tests our micro-ecc, aes_cfb, and gmac implementations
# using OpenSSL-based stubs of the libnx API
option(CHIAKI_ENABLE_LIBNX_TEST "Enable libnx crypto backend test" OFF)

if(CHIAKI_ENABLE_LIBNX_TEST)
	# Find required packages for chiaki-lib-libnx
	find_package(PkgConfig REQUIRED)
	pkg_search_module(MINIUPNPC_LIBNX REQUIRED miniupnpc IMPORTED_TARGET)
	pkg_search_module(JSONC_LIBNX REQUIRED json-c IMPORTED_TARGET)

	# Collect all chiaki-lib source files for the libnx build
	set(CHIAKI_LIB_LIBNX_SOURCES
		${CMAKE_SOURCE_DIR}/lib/src/common.c
		${CMAKE_SOURCE_DIR}/lib/src/sock.c
		${CMAKE_SOURCE_DIR}/lib/src/session.c
		${CMAKE_SOURCE_DIR}/lib/src/thread.c
		${CMAKE_SOURCE_DIR}/lib/src/base64.c
		${CMAKE_SOURCE_DIR}/lib/src/http.c
		${CMAKE_SOURCE_DIR}/lib/src/log.c
		${CMAKE_SOURCE_DIR}/lib/src/ctrl.c
		${CMAKE_SOURCE_DIR}/lib/src/rpcrypt.c
		${CMAKE_SOURCE_DIR}/lib/src/takion.c
		${CMAKE_SOURCE_DIR}/lib/src/senkusha.c
		${CMAKE_SOURCE_DIR}/lib/src/streamconnection.c
		${CMAKE_SOURCE_DIR}/lib/src/ecdh.c
		${CMAKE_SOURCE_DIR}/lib/src/launchspec.c
		${CMAKE_SOURCE_DIR}/lib/src/random.c
		${CMAKE_SOURCE_DIR}/lib/src/gkcrypt.c
		${CMAKE_SOURCE_DIR}/lib/src/audio.c
		${CMAKE_SOURCE_DIR}/lib/src/audioreceiver.c
		${CMAKE_SOURCE_DIR}/lib/src/audiosender.c
		${CMAKE_SOURCE_DIR}/lib/src/videoreceiver.c
		${CMAKE_SOURCE_DIR}/lib/src/frameprocessor.c
		${CMAKE_SOURCE_DIR}/lib/src/packetstats.c
		${CMAKE_SOURCE_DIR}/lib/src/discovery.c
		${CMAKE_SOURCE_DIR}/lib/src/congestioncontrol.c
		${CMAKE_SOURCE_DIR}/lib/src/stoppipe.c
		${CMAKE_SOURCE_DIR}/lib/src/reorderqueue.c
		${CMAKE_SOURCE_DIR}/lib/src/discoveryservice.c
		${CMAKE_SOURCE_DIR}/lib/src/feedback.c
		${CMAKE_SOURCE_DIR}/lib/src/feedbacksender.c
		${CMAKE_SOURCE_DIR}/lib/src/controller.c
		${CMAKE_SOURCE_DIR}/lib/src/takionsendbuffer.c
		${CMAKE_SOURCE_DIR}/lib/src/time.c
		${CMAKE_SOURCE_DIR}/lib/src/fec.c
		${CMAKE_SOURCE_DIR}/lib/src/regist.c
		${CMAKE_SOURCE_DIR}/lib/src/opusdecoder.c
		${CMAKE_SOURCE_DIR}/lib/src/opusencoder.c
		${CMAKE_SOURCE_DIR}/lib/src/orientation.c
		${CMAKE_SOURCE_DIR}/lib/src/bitstream.c
		${CMAKE_SOURCE_DIR}/lib/src/remote/holepunch.c
		${CMAKE_SOURCE_DIR}/lib/src/remote/rudp.c
		${CMAKE_SOURCE_DIR}/lib/src/remote/rudpsendbuffer.c
		# libnx crypto sources
		${CMAKE_SOURCE_DIR}/lib/src/crypto/libnx/microecc/uECC.c
		${CMAKE_SOURCE_DIR}/lib/src/crypto/libnx/aes_cfb.c
		${CMAKE_SOURCE_DIR}/lib/src/crypto/libnx/gmac.c
		# libnx stubs (OpenSSL implementations)
		${CMAKE_CURRENT_SOURCE_DIR}/libnx_stubs/libnx_crypto_stubs.c
	)

	# Protobuf sources (need explicit paths since PARENT_SCOPE only goes to lib/)
	set(CHIAKI_LIB_LIBNX_PROTO_SOURCES "${CMAKE_BINARY_DIR}/lib/protobuf/takion.pb.c")

	# Build chiaki-lib with libnx crypto backend
	add_library(chiaki-lib-libnx STATIC ${CHIAKI_LIB_LIBNX_SOURCES} ${CHIAKI_LIB_LIBNX_PROTO_SOURCES})
	set_source_files_properties(${CHIAKI_LIB_LIBNX_PROTO_SOURCES} PROPERTIES GENERATED TRUE)
	add_dependencies(chiaki-lib-libnx chiaki-pb)

	# libnx stubs MUST come first to override switch/* headers
	target_include_directories(chiaki-lib-libnx BEFORE PUBLIC
		"${CMAKE_CURRENT_SOURCE_DIR}/libnx_stubs"
	)
	target_include_directories(chiaki-lib-libnx PUBLIC
		"${CMAKE_SOURCE_DIR}/lib/include"
		"${CMAKE_SOURCE_DIR}/lib/src"
		"${CMAKE_BINARY_DIR}/lib/include"
		"${CMAKE_BINARY_DIR}/lib/protobuf"
	)

	# Define CHIAKI_LIB_ENABLE_LIBNX_CRYPTO for libnx crypto code paths
	target_compile_definitions(chiaki-lib-libnx PUBLIC CHIAKI_LIB_ENABLE_LIBNX_CRYPTO)

	# Link dependencies
	find_package(Threads REQUIRED)
	find_package(OpenSSL REQUIRED)
	target_link_libraries(chiaki-lib-libnx
		Threads::Threads
		OpenSSL::Crypto
		Nanopb::nanopb
		Jerasure::Jerasure
		PkgConfig::MINIUPNPC_LIBNX
		PkgConfig::JSONC_LIBNX
		CURL::libcurl
	)

	if(CHIAKI_LIB_ENABLE_OPUS)
		target_link_libraries(chiaki-lib-libnx ${Opus_LIBRARIES})
	endif()

	# Build test executable with libnx backend
	add_executable(chiaki-unit-libnx
		main.c
		http.c
		rpcrypt.c
		gkcrypt.c
		takion.c
		seqnum.c
		keystate.c
		reorderqueue.c
		fec.c
		test_log.c
		bitstream.c
		regist.c
	)

	target_link_libraries(chiaki-unit-libnx chiaki-lib-libnx munit)

	add_test(unit-libnx chiaki-unit-libnx)
endif()
