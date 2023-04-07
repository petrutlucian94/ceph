#!/usr/bin/env bash

# MINGW Settings:
# Due to inconsistencies between distributions, mingw versions, binaries,
# and directories must be determined (or defined) prior to building.

# This script expects the following variables:
# * OS - currently ubuntu, rhel, or suse. In the future we may attempt to
#   detect the platform.
# * MINGW_CMAKE_FILE - if set, a cmake toolchain file will be created
# * MINGW_POSIX_FLAGS - if set, Mingw Posix compatibility mode will be
#                       enabled by defining the according flags.
# * USE_MINGW_LLVM - allows using the mingw llvm toolchain
# * MINGW_LLVM_DIR - allows specifying the mingw-llvm toolchain location.
#                    If unset, we'll use the default path from build.deps.

SCRIPT_DIR="$(dirname "$BASH_SOURCE")"
SCRIPT_DIR="$(realpath "$SCRIPT_DIR")"

if [[ -n USE_MINGW_LLVM ]]; then
    MINGW_LLVM_DIR=${MINGW_LLVM_DIR:-"$SCRIPT_DIR/build.deps/mingw-llvm"}
fi

# -Common mingw settings-
MINGW_PREFIX="x86_64-w64-mingw32-"
MINGW_BASE="x86_64-w64-mingw32"
MINGW_CPP="${MINGW_BASE}-c++"
MINGW_DLLTOOL="${MINGW_BASE}-dlltool"
MINGW_WINDRES="${MINGW_BASE}-windres"
MINGW_STRIP="${MINGW_BASE}-strip"
MINGW_OBJCOPY="${MINGW_BASE}-objcopy"

mingwVersion="$(${MINGW_CPP}${mingwPosix} -dumpversion)"

if [[ -n USE_MINGW_LLVM ]]; then
    mingwCompiler="clang"
    # This package isn't currently provided by Linux distributions, we're
    # fetching it from Github.
    export PATH="$MINGW_LLVM_DIR/bin:$PATH"
    mingwPosix=""
    mingwX64IncludeDir="$MINGW_LLVM_DIR/x86_64-w64-mingw32/include"
    mingwX64BinDir="$MINGW_LLVM_DIR/x86_64-w64-mingw32/bin"
    mingwX64LibDir="$MINGW_LLVM_DIR/x86_64-w64-mingw32/lib"
    mingwTargetLibDir="$mingwX64BinDir"
    mingwLibpthreadDir="$mingwX64BinDir"
    PTW32Include="$mingwX64IncludeDir"
    PTW32Lib="$mingwX64LibDir"
else
    mingwCompiler="gcc"
    # -Distribution specific mingw settings-
    case "$OS" in
        ubuntu)
           mingwPosix="-posix"
           mingwLibDir="/usr/lib/gcc"
           mingwTargetLibDir="${mingwLibDir}/${MINGW_BASE}/${mingwVersion}"
           mingwLibpthreadDir="/usr/${MINGW_BASE}/lib"
           PTW32Include=/usr/share/mingw-w64/include
           PTW32Lib=/usr/x86_64-w64-mingw32/lib
          ;;
        rhel)
            mingwPosix=""
            mingwLibDir="/usr/lib64/gcc"
            mingwTargetLibDir="/usr/${MINGW_BASE}/sys-root/mingw/bin"
            mingwLibpthreadDir="$mingwTargetLibDir"
            PTW32Include=/usr/x86_64-w64-mingw32/sys-root/mingw/include
            PTW32Lib=/usr/x86_64-w64-mingw32/sys-root/mingw/lib
           ;;
        suse)
            mingwPosix=""
            mingwLibDir="/usr/lib64/gcc"
            mingwTargetLibDir="/usr/${MINGW_BASE}/sys-root/mingw/bin"
            mingwLibpthreadDir="$mingwTargetLibDir"
            PTW32Include=/usr/x86_64-w64-mingw32/sys-root/mingw/include
            PTW32Lib=/usr/x86_64-w64-mingw32/sys-root/mingw/lib
            ;;
        *)
            echo "$ID is unknown, automatic mingw configuration is not possible."
            exit 1
            ;;
    esac
fi

# -Common mingw settings, dependent upon distribution specific settings-
MINGW_FIND_ROOT_LIB_PATH="${mingwLibDir}/\${TOOLCHAIN_PREFIX}/${mingwVersion}"
MINGW_CC="${MINGW_BASE}-${mingwCompiler}${mingwPosix}"
MINGW_CXX="${MINGW_BASE}-${mingwCompiler}++${mingwPosix}"
# End MINGW configuration


if [[ -n $MINGW_CMAKE_FILE ]]; then
    cat > $MINGW_CMAKE_FILE <<EOL
set(CMAKE_SYSTEM_NAME Windows)
set(TOOLCHAIN_PREFIX ${MINGW_BASE})
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# We'll need to use posix threads in order to use
# C++11 features, such as std::thread.
set(CMAKE_C_COMPILER \${TOOLCHAIN_PREFIX}-${mingwCompiler}${mingwPosix})
set(CMAKE_CXX_COMPILER \${TOOLCHAIN_PREFIX}-${mingwCompiler}++${mingwPosix})
set(CMAKE_RC_COMPILER \${TOOLCHAIN_PREFIX}-windres)

set(CMAKE_FIND_ROOT_PATH /usr/\${TOOLCHAIN_PREFIX} ${MINGW_FIND_ROOT_LIB_PATH})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# TODO: consider switching this to "ONLY". The issue with
# that is that all our libs should then be under
# CMAKE_FIND_ROOT_PATH and CMAKE_PREFIX_PATH would be ignored.
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
EOL
    if [[ -n $MINGW_POSIX_FLAGS ]]; then
        cat >> $MINGW_CMAKE_FILE <<EOL
# Some functions (e.g. localtime_r) will not be available unless we set
# the following flag.
add_definitions(-D_POSIX=1)
add_definitions(-D_POSIX_C_SOURCE=1)
add_definitions(-D_POSIX_=1)
add_definitions(-D_POSIX_THREADS=1)
EOL
    fi

    if [[ -n $USE_MINGW_LLVM ]]; then
        cat >> $MINGW_CMAKE_FILE <<EOL
add_definitions(-I$mingwX64IncludeDir)
add_definitions(-march=native)
add_definitions(-Wno-unknown-attributes)
EOL
    fi
fi
