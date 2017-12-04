#!/usr/bin/env bash

#abort if any command fails
set -e

mkdir -p build
builddir=$(readlink -f build)

export CPPFLAGS=-I$builddir/include
export CFLAGS=-I$builddir/include
export LDFLAGS=-L$builddir/lib

help () {
    echo "$1: libmmap build script"
    echo ""
    echo "Commands:"
    echo "  <default>   Build everything"
    echo "  debug       Build in debug mode"
    echo "  clean       Remove build"
    echo "  no-gghlite  Build without gghlite"
    echo "  help        Print this info and exit"
}

gghlite='y'
if [ x"$1" == x"" ]; then
    flags=''
elif [ x"$1" == x"debug" ]; then
    echo "DEBUG mode"
    flags='-DCMAKE_BUILD_TYPE=Debug'
elif [ x"$1" == x"clean" ]; then
    rm -rf build libaesrand clt13 gghlite
    exit 0
elif [ x"$1" == x"no-gghlite" ]; then
    echo "Disable gghlite"
    flags='-DHAVE_GGHLITE=OFF'
    gghlite='n'
elif [ x"$1" == x"help" ]; then
    help $0
    exit 0
else
    echo "error: unknown command '$1'"
    help $0
    exit 0
fi

build () {
    path=$1
    url=$2
    branch=$3

    echo
    echo "building $path ($url $branch)"
    echo

    if [ ! -d $path ]; then
        git clone $url $path -b $branch;
    else
        pushd $path; git pull origin $branch; popd
    fi
    pushd $path
        cmake -DCMAKE_INSTALL_PREFIX="${builddir}" .
        make
        make install
    popd
}

echo
echo builddir = $builddir
echo

build libaesrand git@github.com:5GenCrypto/libaesrand cmake
build clt13      git@github.com:5GenCrypto/clt13 cmake
if [ x"$gghlite" = x"y" ]; then
   build gghlite    git@github.com:5GenCrypto/gghlite-flint master
fi

rm -rf CMakeCache.txt CMakeFiles
cmake "${flags}" .
make
