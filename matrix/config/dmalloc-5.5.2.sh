#!/bin/bash

# 生成Makefile之后，如果编译失败，可以将-O2改为-Os。

target=dmalloc

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

