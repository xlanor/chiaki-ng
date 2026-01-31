#!/bin/bash
# Build and run chiaki tests in Docker
# Usage: ./scripts/run-tests.sh [--libnx] [--pmull] [--no-build]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_IMAGE="chiaki-test-builder"
DOCKER_IMAGE_ARM64="chiaki-test-builder-arm64"

RUN_LIBNX_TEST=false
RUN_PMULL_TEST=false
SKIP_BUILD=false

for arg in "$@"; do
    case $arg in
        --libnx)
            RUN_LIBNX_TEST=true
            shift
            ;;
        --pmull)
            RUN_PMULL_TEST=true
            RUN_LIBNX_TEST=true  # PMULL implies libnx
            shift
            ;;
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--libnx] [--pmull] [--no-build]"
            echo ""
            echo "Options:"
            echo "  --libnx     Also build and run the libnx crypto backend tests"
            echo "  --pmull     Test ARM NEON PMULL GHASH (runs in ARM64 Docker via QEMU)"
            echo "  --no-build  Skip cmake configuration (reuse existing build)"
            echo ""
            exit 0
            ;;
    esac
done

if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
    echo "Building Docker image $DOCKER_IMAGE..."
    docker build -t "$DOCKER_IMAGE" -f "$SCRIPT_DIR/Dockerfile.jammy" "$PROJECT_DIR"
fi

CMAKE_OPTS="-DCHIAKI_ENABLE_TESTS=ON"
CMAKE_OPTS="$CMAKE_OPTS -DCHIAKI_ENABLE_GUI=OFF"
CMAKE_OPTS="$CMAKE_OPTS -DCHIAKI_ENABLE_CLI=OFF"
CMAKE_OPTS="$CMAKE_OPTS -DCHIAKI_ENABLE_STEAM_SHORTCUT=OFF"
CMAKE_OPTS="$CMAKE_OPTS -DCHIAKI_LIB_ENABLE_OPUS=OFF"

if [ "$RUN_LIBNX_TEST" = true ]; then
    CMAKE_OPTS="$CMAKE_OPTS -DCHIAKI_ENABLE_LIBNX_TEST=ON"
fi

docker run --rm -v "$PROJECT_DIR:/src" -w /src "$DOCKER_IMAGE" bash -c "
    set -e

    # Install extra dependencies
    apt-get update -qq
    apt-get install -y -qq libminiupnpc-dev libjson-c-dev protobuf-compiler python3-protobuf

    if [ '$SKIP_BUILD' != 'true' ]; then
        rm -rf build
        mkdir -p build
        cd build
        cmake .. $CMAKE_OPTS
    else
        cd build
    fi

    # Build and run standard tests
    echo ''
    echo '========================================='
    echo 'Building chiaki-unit (OpenSSL backend)...'
    echo '========================================='
    make chiaki-unit -j\$(nproc)

    echo ''
    echo '========================================='
    echo 'Running chiaki-unit tests...'
    echo '========================================='
    ./test/chiaki-unit

    # Build and run libnx tests if requested (table-driven, x86_64)
    if [ '$RUN_LIBNX_TEST' = 'true' ] && [ '$RUN_PMULL_TEST' != 'true' ]; then
        echo ''
        echo '========================================='
        echo 'Building chiaki-unit-libnx (libnx crypto backend)...'
        echo '========================================='
        make chiaki-unit-libnx -j\$(nproc)

        echo ''
        echo '========================================='
        echo 'Running chiaki-unit-libnx tests...'
        echo '========================================='
        ./test/chiaki-unit-libnx
    fi

    echo ''
    echo '========================================='
    echo 'All tests passed!'
    echo '========================================='
"

# Run PMULL tests in ARM64 Docker container via QEMU
if [ "$RUN_PMULL_TEST" = true ]; then
    echo ""
    echo "========================================="
    echo "Setting up ARM64 emulation via QEMU..."
    echo "========================================="

    # Register QEMU binfmt handlers using tonistiigi/binfmt (works better with Docker)
    docker run --rm --privileged tonistiigi/binfmt --install arm64

    # Create buildx builder if it doesn't exist
    if ! docker buildx inspect arm64-builder &>/dev/null 2>&1; then
        echo "Creating buildx builder for ARM64..."
        docker buildx create --name arm64-builder --use
    else
        docker buildx use arm64-builder
    fi

    # Build and run tests inside Docker build (workaround for binfmt issues with docker run)
    echo "Building and running PMULL tests in ARM64 buildx..."
    echo "(Tests run during build - if build succeeds, tests passed)"
    echo ""
    docker buildx build --platform linux/arm64 --progress=plain -f "$SCRIPT_DIR/Dockerfile.arm64-pmull-test" "$PROJECT_DIR"
fi
