#!/bin/bash

target=valgrind

if [ -z $ROOT_DIR ];then
    echo "./configure"
    sleep 2
    ./configure
    make clean
    make 
else
    echo "./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target"
    sleep 2
    ./configure --host=$HOST_CHAIN --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target
    make clean
    make 
    make install
fi

