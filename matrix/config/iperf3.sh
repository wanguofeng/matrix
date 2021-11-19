#!/bin/bash

target=iperf3

if [ -z $ROOT_DIR ];then
    echo "./configure"
    sleep 2
    ./configure
    make clean
    make 
else
    echo "./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target LDFLAGS=-L$ROOT_DIR/output/$TARGET_PLATFORM/openssl/lib CFLAGS=-static CXXFLAGS=-static"
    sleep 2
    ./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target LDFLAGS=-L$ROOT_DIR/output/$TARGET_PLATFORM/openssl/lib CFLAGS=-static CXXFLAGS=-static
    make clean
    make 
    make install
fi

