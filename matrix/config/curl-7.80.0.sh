#!/bin/bash

target=curl

if [ -z $ROOT_DIR ];then
    echo "./configure --with-mbedtls"
    sleep 2
    ./configure --with-mbedtls
    make clean
    make 
else
    echo "./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target --with-mbedtls"
    sleep 2
    ./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target --with-mbedtls
    make clean
    make 
    make install
fi

