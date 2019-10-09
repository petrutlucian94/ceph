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
echo "using gcc : mingw32 : x86_64-w64-mingw32-g++ ;" > user-config.jam
./boostrap.sh
./b2 install --user-config=user-config.jam toolset=gcc-mingw32 \
    target-os=windows release \
    threadapi=win32 --prefix=$boostDir \
    address-model=64 architecture=x86 \
    binary-format=pe abi=ms -j 8 \
    --without-python --without-mpi -sNO_BZIP2=1 -sNO_ZLIB=1
# ./b2 toolset=gcc-mingw32 target-os=windows threadapi=win32 \
#     --build-type=complete --prefix=/usr/x86_64-w64-mingw32/local \
#     --layout=tagged --without-python -sNO_BZIP2=1 -sNO_ZLIB=1

./b2 install --user-config=user-config.jam toolset=gcc-mingw32 \
    target-os=windows release \
    threadapi=win32 --prefix=$boostDir \
    address-model=64 architecture=x86 -j 8 \

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
