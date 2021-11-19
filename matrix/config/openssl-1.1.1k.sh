#!/bin/bash

target=openssl

if [ -z $ROOT_DIR ];then
    echo "./configure"
    sleep 2
    ./Configure no-asm no-shared no-async CC=gcc
    make clean
    make 
else
    if [ $TARGET_PLATFORM == "amlogic" ];then
        echo "./Configure no-asm no-shared no-async --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target CROSS_COMPILE=$HOST_CHAIN- CC=gcc"
        sleep 2
        ./Configure no-asm no-shared no-async --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target CROSS_COMPILE=$HOST_CHAIN- CC=gcc
    else
        echo "./Configure linux-generic32 no-asm no-shared no-async --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target CROSS_COMPILE=$HOST_CHAIN- CC=gcc"
        sleep 2
        ./Configure linux-generic32 no-asm no-shared no-async --prefix=$ROOT_DIR/output/$TARGET_PLATFORM/$target CROSS_COMPILE=$HOST_CHAIN- CC=gcc
    fi
    make clean
    make 
    make install
fi

