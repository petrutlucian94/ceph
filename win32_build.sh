set -e

# This simple script may be used as a sample. All the paths are hardcoded.
# At some point, we'll probably provide a docker image for building ceph
# for Windows.

cephDir="/data2/workspace/ceph"
depsDir="/data2/workspace/ceph_deps"
buildDir="${cephDir}/build"

depsSrcDir=/data2/workspace/ceph_deps/src
depsToolsetDir="/data2/workspace/ceph_deps/mingw"

lz4Dir="${depsToolsetDir}/lz4"
sslDir="${depsToolsetDir}/openssl"
curlDir="${depsToolsetDir}/curl"
boostDir="${depsToolsetDir}/boost"
zlibDir="${depsToolsetDir}/zlib"
backtraceDir="${depsToolsetDir}/backtrace"

# cmakeGenerator="Ninja"
cmakeArchitecture="x64"
# toolset="Clang"

pyVersion="3.6"

depsDirs="$lz4Dir;$curlDir;$sslDir;$boostDir;$zlibDir;$backtraceDir"

# That's actually a dll, we may want to rename the file.
lz4Lib="${lz4Dir}/lib/liblz4.so.1.9.2"
lz4Include="${lz4Dir}/lib"
curlLib="${curlDir}/lib/libcurl.dll.a"
curlInclude="${curlDir}/include"


# cmake doesn't properly recognize this for some reason.
# cc=$(where.exe clang.exe) -replace "\\", "/"
# cxx=$(where.exe clang++.exe) -replace "\\", "/"

mkdir -p $buildDir
pushd .
cd $cephDir

# We'll need to cross compile Boost.Python before enabling
# "WITH_MGR".
echo "Generating solution. Log: ${buildDir}/cmake.log"
cmake=$(which cmake)
# cmake=/data2/workspace/CMake/bin/cmake

cd $buildDir
$cmake -D CMAKE_PREFIX_PATH=$depsDirs \
      -D CMAKE_TOOLCHAIN_FILE="$cephDir/cmake/toolchains/mingw32.cmake" \
      -D WITH_PYTHON2=OFF -D WITH_PYTHON3=${pyVersion} \
      -D MGR_PYTHON_VERSION=${pyVersion} \
      -D WITH_RDMA=OFF -D WITH_OPENLDAP=OFF \
      -D WITH_GSSAPI=OFF -D WITH_FUSE=OFF -D WITH_XFS=OFF \
      -D WITH_BLUESTORE=OFF -D WITH_LEVELDB=OFF \
      -D WITH_LTTNG=OFF -D WITH_BABELTRACE=OFF \
      -D WITH_SYSTEM_BOOST=ON -D WITH_MGR=OFF \
      -D WITH_LIBCEPHFS=OFF -D WITH_KRBD=OFF -D WITH_RADOSGW=OFF \
      -D ENABLE_SHARED=ON -D WITH_RBD=OFF -D BUILD_GMOCK=OFF \
      -D WITH_CEPHFS=OFF -D WITH_MANPAGE=OFF \
      -D WITH_MGR_DASHBOARD_FRONTEND=OFF -D WITH_SYSTEMD=OFF -D WITH_TESTS=OFF \
      -D LZ4_INCLUDE_DIR=$lz4Include -D LZ4_LIBRARY=$lz4Lib \
      -D Backtrace_Header="$backtraceDir/include/backtrace.h" \
      -D Backtrace_INCLUDE_DIR="$backtraceDir/include" \
      -D Backtrace_LIBRARY="$backtraceDir/lib/libbacktrace.dll.a" \
      $cephDir \
      # --trace-expand > "${buildDir}/cmake.log" 2>&1
      # -T $toolset \
      # -G $cmakeGenerator -A $cmakeArchitecture \
#
#       -D Boost_INCLUDE_DIR=$boostIncludeDir \
#       -D BOOST_ROOT=$boostDir -D BOOST_LIBRARYDIR=$boostLibDir
#       -D MSVC_TOOLSET_VERSION="142" -DBoost_DEBUG=ON \
      # \
      # -D CURL_LIBRARY=$curlLib -D CURL_INCLUDE_DIR=$curlInclude \
      # -D OPENSSL_INCLUDE_DIR="$sslDir/include" \
      # -D OPENSSL_ROOT_DIR=$sslDir \
      # -D OPENSSL_CRYPTO_LIBRARY="$sslDir/lib/libcrypto.a" \


# TODO: switch to ninja
echo "Building solution. Log: ${buildDir}/build.log"
# MSBuild.exe build\ceph.sln /m > "${buildDir}/build.log" 2>&1

popd
