# This is just a template atm.

depsDir="/data2/workspace/ceph_deps"
depsSrcDir=/data2/workspace/ceph_deps/src
depsMingwDir="/data2/workspace/ceph_deps/mingw"

# Can't easily specify build dir for lz4
lz4Dir="${depsMingwDir}/lz4"
# TODO: fetch configurable openssl version
sslVersion="1.1.1d"
sslDir="${depsMingwDir}/openssl"
sslSrcDir="${depsSrcDir}/openssl-${sslVersion}"
curlSrcDir="${depsSrcDir}/curl"
curlDir="${depsMingwDir}/curl"
boostSrcDir="${boostSrcDir}/boost"
boostDir="${depsMingwDir}/boost"
zlibDir="${depsMingwDir}/zlib"
zlibSrcDir="${depsSrcDir}/zlib"
backtraceDir="${depsMingwDir}/backtrace"
backtraceSrcDir="${depsSrcDir}/backtrace"
snappySrcDir="${depsSrcDir}/snappy"
snappyDir="${depsMingwDir}/snappy"

MINGW_PREFIX="x86_64-w64-mingw32-"

MINGW_CMAKE_FILE=/tmp/mingw.cmake
cat > $MINGW_CMAKE_FILE <<EOL
set(CMAKE_SYSTEM_NAME Windows)
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# We'll need to use posix threads in order to use
# C++11 features, such as std::thread.
set(CMAKE_C_COMPILER \${TOOLCHAIN_PREFIX}-gcc-posix)
set(CMAKE_CXX_COMPILER \${TOOLCHAIN_PREFIX}-g++-posix)
set(CMAKE_RC_COMPILER \${TOOLCHAIN_PREFIX}-windres)

set(CMAKE_FIND_ROOT_PATH /usr/\${TOOLCHAIN_PREFIX} /usr/lib/gcc/\${TOOLCHAIN_PREFIX}/7.3-posix)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
EOL

sudo apt-get -y install mingw-w64 cmake pkg-config python3-dev python3-pip
sudo python3 -m pip install cython

cd $depsMingwDir
# make BUILD_STATIC=no CC=x86_64-w64-mingw32-gcc \
#     DLLTOOL=x86_64-w64-mingw32-dlltool OS=Windows_NT
# make BUILD_STATIC=no CC=x86_64-w64-mingw32-gcc \
#     DLLTOOL=x86_64-w64-mingw32-dlltool OS=Windows_NT \
#     -C /data2/workspace/ceph_deps/mingw/lz4_build ../lz4/Makefile
curl "https://www.openssl.org/source/${sslVersion}.tar.gz" | \
    tar xvz
pushd $sslSrcDir
CROSS_COMPILE="x86_64-w64-mingw32-" ./Configure \
    mingw64 shared --prefix=$sslDir
# CROSS_COMPILE="x86_64-w64-mingw32-" ./Configure \
#     --prefix=$sslDir mingw64 no-asm no-shared
make depend
make
make install


cd $curlSrcDir
./configure --prefix=$curlDir --with-ssl=$sslDir --host=x86_64-w64-mingw32

make
make install

cd $boostSrcDir
echo "using gcc : mingw32 : x86_64-w64-mingw32-g++-posix ;" > user-config.jam

# Workaround for https://github.com/boostorg/thread/issues/156
# Older versions of mingw provided a different pthread lib.
sed -i 's/lib$(libname)GC2.a/lib$(libname).a/g' ./libs/thread/build/Jamfile.v2
sed -i 's/mthreads/pthreads/g' ./tools/build/src/tools/gcc.py
sed -i 's/mthreads/pthreads/g' ./tools/build/src/tools/gcc.jam

sed -i 's/pthreads/mthreads/g' ./tools/build/src/tools/gcc.py
sed -i 's/pthreads/mthreads/g' ./tools/build/src/tools/gcc.jam

export PTW32_INCLUDE=/usr/share/mingw-w64/include
export PTW32_LIB=/usr/x86_64-w64-mingw32/lib

# Fix getting Windows page size
cat > thread_data.patch <<EOL
--- boost/thread/pthread/thread_data.hpp        2019-10-11 15:26:15.678703586 +0300
+++ boost/thread/pthread/thread_data.hpp.new    2019-10-11 15:26:07.321463698 +0300
@@ -32,6 +32,10 @@
 # endif
 #endif

+#if defined(_WIN32)
+#include <windows.h>
+#endif
+
 #include <pthread.h>
 #include <unistd.h>

@@ -54,6 +58,10 @@
           if (size==0) return;
 #ifdef BOOST_THREAD_USES_GETPAGESIZE
           std::size_t page_size = getpagesize();
+#elif _WIN32
+          SYSTEM_INFO system_info;
+          ::GetSystemInfo (&system_info);
+          std::size_t page_size = system_info.dwPageSize;
 #else
           std::size_t page_size = ::sysconf( _SC_PAGESIZE);
 #endif
EOL

# Use pthread if requested
cat > thread.patch <<EOL
--- boost/asio/detail/thread.hpp        2019-10-11 16:26:11.191094656 +0300
+++ boost/asio/detail/thread.hpp.new    2019-10-11 16:26:03.310542438 +0300
@@ -19,6 +19,8 @@

 #if !defined(BOOST_ASIO_HAS_THREADS)
 # include <boost/asio/detail/null_thread.hpp>
+#elif defined(BOOST_ASIO_HAS_PTHREADS)
+# include <boost/asio/detail/posix_thread.hpp>
 #elif defined(BOOST_ASIO_WINDOWS)
 # if defined(UNDER_CE)
 #  include <boost/asio/detail/wince_thread.hpp>
@@ -27,8 +29,6 @@
 # else
 #  include <boost/asio/detail/win_thread.hpp>
 # endif
-#elif defined(BOOST_ASIO_HAS_PTHREADS)
-# include <boost/asio/detail/posix_thread.hpp>
 #elif defined(BOOST_ASIO_HAS_STD_THREAD)
 # include <boost/asio/detail/std_thread.hpp>
 #else
@@ -41,6 +41,8 @@

 #if !defined(BOOST_ASIO_HAS_THREADS)
 typedef null_thread thread;
+#elif defined(BOOST_ASIO_HAS_PTHREADS)
+typedef posix_thread thread;
 #elif defined(BOOST_ASIO_WINDOWS)
 # if defined(UNDER_CE)
 typedef wince_thread thread;
@@ -49,8 +51,6 @@
 # else
 typedef win_thread thread;
 # endif
-#elif defined(BOOST_ASIO_HAS_PTHREADS)
-typedef posix_thread thread;
 #elif defined(BOOST_ASIO_HAS_STD_THREAD)
 typedef std_thread thread;
 #endif
EOL

# TODO: send this upstream and maybe use a fork until it merges
patch -N boost/thread/pthread/thread_data.hpp thread_data.patch
patch -N boost/asio/detail/thread.hpp thread.hpp

./bootstrap.sh

./b2 install --user-config=user-config.jam toolset=gcc-mingw32 \
    target-os=windows release \
    threadapi=pthread --prefix=$boostDir \
    address-model=64 architecture=x86 \
    binary-format=pe abi=ms -j 8 \
    --without-python --without-mpi -sNO_BZIP2=1 -sNO_ZLIB=1 \

 # cxxflags=-DPTHREADS cxxflags=-DBOOST_THREAD_POSIX cxxflags=-pthread cxxflags=-DTHREAD
# ./b2 toolset=gcc-mingw32 target-os=windows threadapi=win32 \
#     --build-type=complete --prefix=/usr/x86_64-w64-mingw32/local \
#     --layout=tagged --without-python -sNO_BZIP2=1 -sNO_ZLIB=1

# ./b2 install --user-config=user-config.jam toolset=gcc-mingw32 \
#     target-os=windows release \
#     threadapi=win32 --prefix=$boostDir \
#     address-model=64 architecture=x86 -j 8 \

cd $depsSrcDir
git clone https://github.com/madler/zlib
# Apparently the configure script is broken...
sed -e s/"PREFIX ="/"PREFIX = x86_64-w64-mingw32-"/ -i win32/Makefile.gcc
make -f win32/Makefile.gcc
make BINARY_PATH=$zlibDir \
     INCLUDE_PATH=$zlibDir/include \
     LIBRARY_PATH=$zlibDir/lib \
     SHARED_MODE=1 \
     -f win32/Makefile.gcc install

# If you ever happen to want to link against installed libraries
# in a given directory, LIBDIR, you must either use libtool, and
# specify the full pathname of the library, or use the `-LLIBDIR'
# flag during linking and do at least one of the following:
#    - add LIBDIR to the `PATH' environment variable
#      during execution
#    - add LIBDIR to the `LD_RUN_PATH' environment variable
#      during linking
#    - use the `-LLIBDIR' linker flag
#    - have your system administrator add LIBDIR to `/etc/ld.so.conf'
git clone https://github.com/ianlancetaylor/libbacktrace
mkdir libbacktrace/build
cd libbacktrace/build
../configure --prefix=$backtraceDir --exec-prefix=$backtraceDir \
             --host x86_64-w64-mingw32 --enable-host-shared
make LDFLAGS="-no-undefined" -j 8
make install

git clone git clone https://github.com/google/snappy
mkdir snappy/build
cd snappy/build

cmake -DCMAKE_INSTALL_PREFIX=$snappyDir \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=ON \
      -DSNAPPY_BUILD_TESTS=OFF \
      -DCMAKE_TOOLCHAIN_FILE=$MINGW_CMAKE_FILE \
      ../
make
make install

cmake -DCMAKE_INSTALL_PREFIX=$snappyDir \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DSNAPPY_BUILD_TESTS=OFF \
      -DCMAKE_TOOLCHAIN_FILE=$MINGW_CMAKE_FILE \
      ../
make
