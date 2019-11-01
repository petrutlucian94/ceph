#!/bin/bash

set -e

SCRIPT_DIR="$(dirname "$BASH_SOURCE")"
SCRIPT_DIR="$(realpath "$SCRIPT_DIR")"

num_vcpus=$(( $(lscpu -p | tail -1 | cut -d "," -f 1) + 1 ))

CEPH_DIR="${CEPH_DIR:-$SCRIPT_DIR}"
BUILD_DIR="${BUILD_DIR:-${CEPH_DIR}/build}"
DEPS_DIR="${DEPS_DIR:-$CEPH_DIR/build.deps}"

CLEAN_BUILD=${CLEAN_BUILD:-}
SKIP_BUILD=${SKIP_BUILD:-}
NUM_WORKERS=${NUM_WORKERS:-$num_vcpus}

depsSrcDir="$DEPS_DIR/src"
depsToolsetDir="$DEPS_DIR/mingw"

lz4Dir="${depsToolsetDir}/lz4"
sslDir="${depsToolsetDir}/openssl"
curlDir="${depsToolsetDir}/curl"
boostDir="${depsToolsetDir}/boost"
zlibDir="${depsToolsetDir}/zlib"
backtraceDir="${depsToolsetDir}/backtrace"
snappyDir="${depsToolsetDir}/snappy"

pyVersion=`python -c "import sys; print('%d.%d' % (sys.version_info.major, sys.version_info.minor))"`

depsDirs="$lz4Dir;$curlDir;$sslDir;$boostDir;$zlibDir;$backtraceDir;$snappyDir"

# That's actually a dll, we may want to rename the file.
lz4Lib="${lz4Dir}/lib/liblz4.so.1.9.2"
lz4Include="${lz4Dir}/lib"
curlLib="${curlDir}/lib/libcurl.dll.a"
curlInclude="${curlDir}/include"

if [[ -n $CLEAN_BUILD ]]; then
    echo "Cleaning up build dir: $BUILD_DIR"
    rm -rf $BUILD_DIR
fi

if [[ ! -d $DEPS_DIR ]]; then
    echo "Preparing dependencies: $DEPS_DIR"
    NUM_WORKERS=$NUM_WORKERS DEPS_DIR=$DEPS_DIR \
        "$SCRIPT_DIR/win32_deps_build.sh"
fi

mkdir -p $BUILD_DIR
cd $BUILD_DIR

# We'll need to cross compile Boost.Python before enabling
# "WITH_MGR".
echo "Generating solution. Log: ${BUILD_DIR}/cmake.log"

# This isn't propagated to some of the subprojects, we'll use an env variable
# for now.
export CMAKE_PREFIX_PATH=$depsDirs

cmake -D CMAKE_PREFIX_PATH=$depsDirs \
      -D CMAKE_TOOLCHAIN_FILE="$CEPH_DIR/cmake/toolchains/mingw32.cmake" \
      -D WITH_PYTHON2=OFF -D WITH_PYTHON3=ON \
      -D MGR_PYTHON_VERSION=$pyVersion \
      -D WITH_RDMA=OFF -D WITH_OPENLDAP=OFF \
      -D WITH_GSSAPI=OFF -D WITH_FUSE=OFF -D WITH_XFS=OFF \
      -D WITH_BLUESTORE=OFF -D WITH_LEVELDB=OFF \
      -D WITH_LTTNG=OFF -D WITH_BABELTRACE=OFF \
      -D WITH_SYSTEM_BOOST=ON -D WITH_MGR=OFF \
      -D WITH_LIBCEPHFS=OFF -D WITH_KRBD=OFF -D WITH_RADOSGW=OFF \
      -D ENABLE_SHARED=ON -D WITH_RBD=ON -D BUILD_GMOCK=OFF \
      -D WITH_CEPHFS=OFF -D WITH_MANPAGE=OFF \
      -D WITH_MGR_DASHBOARD_FRONTEND=OFF -D WITH_SYSTEMD=OFF -D WITH_TESTS=OFF \
      -D LZ4_INCLUDE_DIR=$lz4Include -D LZ4_LIBRARY=$lz4Lib \
      -D Backtrace_Header="$backtraceDir/include/backtrace.h" \
      -D Backtrace_INCLUDE_DIR="$backtraceDir/include" \
      -D Backtrace_LIBRARY="$backtraceDir/lib/libbacktrace.dll.a" \
      -D Boost_THREADAPI="pthread" \
      $CEPH_DIR  2>&1 | tee "${BUILD_DIR}/cmake.log"

# TODO: switch to ninja
echo "Running make using $NUM_WORKERS workers. Log: ${BUILD_DIR}/make.log"
cd $BUILD_DIR

if [[ -z $SKIP_BUILD ]]; then
    make -j $NUM_WORKERS 2>&1 | tee "${BUILD_DIR}/make.log"
fi
