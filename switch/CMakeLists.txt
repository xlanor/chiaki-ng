
##################
# borealis dependency
##################
# Dependencies

# Sets the minimum version of CMake required to build the native library.
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-std=gnu++20>)

file(GLOB_RECURSE BOREALIS_SOURCES
    "borealis/library/extern/yoga/yoga/*.cpp"
    "borealis/library/extern/tweeny/*.cc"
    "borealis/library/extern/switch-libpulsar/src/*.c"
    "borealis/library/lib/views/cells/*.cpp"
    "borealis/library/lib/views/widgets/*.cpp"
	"borealis/library/lib/core/*.cpp"
	"borealis/library/lib/platforms/switch/*.cpp"
	"borealis/library/lib/views/*.cpp"
)
# do not include
# borealis/library/lib/switch_wrapper.c
# switch functions are in switch/src/main.cpp
set(BOREALIS_SOURCE
    borealis/library/lib/extern/libretro-common/features/features_cpu.c
    borealis/library/lib/extern/libretro-common/encodings/encoding_utf.c
    borealis/library/lib/extern/libretro-common/compat/compat_strl.c
    borealis/library/lib/extern/nanovg/nanovg.c
    borealis/library/lib/extern/tinyxml2/tinyxml2.cpp
    borealis/library/lib/extern/glad/glad.c
	borealis/library/lib/extern/nxfmtwrapper/format.cpp
	${BOREALIS_SOURCES}
	borealis/library/lib/core/touch/tap_gesture.cpp
	borealis/library/lib/core/touch/scroll_gesture.cpp
	borealis/library/lib/core/touch/pan_gesture.cpp
)

add_library(borealis STATIC ${BOREALIS_SOURCE})
set_property(TARGET borealis PROPERTY CXX_STANDARD 20)
target_include_directories(borealis PRIVATE
)
target_include_directories(borealis PUBLIC
	borealis/library/include
    borealis/library/include/borealis/extern
	borealis/library/lib/extern/yoga
	borealis/library/lib/extern/tweeny/include
	borealis/library/lib/extern/fmt/include
	borealis/library/lib/extern/tweeny/include
	borealis/library/lib/extern/switch-libpulsar/include
	borealis/library/include/borealis/extern/glad
	borealis/library/include/borealis/extern/nanovg
	borealis/library/include/borealis/extern/tinyxml2
	borealis/library/include/borealis/extern/libretro-common
    borealis/library/include/borealis/core
    borealis/library/include/borealis/platforms/switch
    borealis/library/include/borealis/views
    borealis/library/include/borealis/views/cells
    borealis/library/include/borealis/views/widgets
)

find_package(glfw3 REQUIRED)
find_library(EGL EGL)
find_library(GLAPI glapi)
find_library(DRM_NOUVEAU drm_nouveau)
target_link_libraries(borealis
	glfw
	${EGL}
	${GLAPI}
	${DRM_NOUVEAU})

if(CHIAKI_IS_SWITCH)
	target_compile_definitions(borealis PUBLIC
		BOREALIS_RESOURCES="romfs:/")
else()
	target_compile_definitions(borealis PUBLIC
		BOREALIS_RESOURCES="./switch/res/")
endif()


##################
# chiaki with borealis
##################

find_package(FFMPEG REQUIRED COMPONENTS avcodec avutil swscale)
find_library(SDL2 SDL2)
find_library(SWRESAMPLE swresample)

add_definitions(-DBRLS_RESOURCES="borealis/resources/" -DYG_ENABLE_EVENTS)

# find -type f | grep -P '\.(h|cpp)$' | sed 's#\./#\t\t#g'
add_executable(chiaki-borealis WIN32
	src/discoverymanager.cpp
	src/settings.cpp
	src/io.cpp
	src/host.cpp
	src/main.cpp
	src/gui.cpp)

set_target_properties(chiaki-borealis PROPERTIES
	CXX_STANDARD 17
	OUTPUT_NAME chiaki)

target_include_directories(chiaki-borealis PRIVATE include)

target_link_libraries(chiaki-borealis
	chiaki-lib
	borealis
	${SDL2}
	FFMPEG::avcodec
	FFMPEG::avutil
	FFMPEG::swscale
	${SWRESAMPLE}
	${SWSCALE})

if(CHIAKI_IS_SWITCH)
	# libnx is forced by the switch toolchain
	find_library(Z z)
	find_library(GLAPI glapi) # TODO: make it transitive from borealis
	find_library(DRM_NOUVEAU drm_nouveau) # TODO: make it transitive from borealis
	target_link_libraries(chiaki-borealis ${Z} ${GLAPI} ${DRM_NOUVEAU})
endif()

install(TARGETS chiaki-borealis
	RUNTIME DESTINATION bin
	BUNDLE DESTINATION bin)

if(CHIAKI_IS_SWITCH)
	add_nro_target(chiaki
		chiaki-borealis
		"Chiaki-ng"
		"StreetPea, xlanor, H0neyBadger and thestr4ng3r"
		"${CHIAKI_VERSION}"
		"${CMAKE_CURRENT_SOURCE_DIR}/nro_icon.jpg"
		"${CMAKE_CURRENT_SOURCE_DIR}/res")
endif()
