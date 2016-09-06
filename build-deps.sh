#!/usr/bin/env bash

#abort if any command fails
set -e

mkdir -p build
builddir=$(readlink -f build)

export CPPFLAGS=-I$builddir/include
export CFLAGS=-I$builddir/include
export LDFLAGS=-L$builddir/lib

build () {
    echo building $1
    path=$1
    url=$2
    branch=$3
    if [ ! -d $path ]; then
        git clone $url $path;
    else
        cd $path; git pull origin $branch; cd ..;
    fi
    cd $1
        mkdir -p build/autoconf
        autoreconf -i
        ./configure --prefix=$builddir --enable-debug
        make
        make install
    cd ..;  
    echo
}

echo
echo builddir = $builddir
echo

build libaesrand https://github.com/5GenCrypto/libaesrand master
build clt13      https://github.com/5GenCrypto/clt13 dev
build gghlite    https://github.com/5GenCrypto/gghlite-flint dev
