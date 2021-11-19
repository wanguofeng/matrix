#!/bin/bash

CUR_DIR=$(pwd)

cd $(dirname $BASH_SOURCE)
PROJECT_DIR=$(dirname `echo $(pwd)/$(basename $BASH_SOURCE)`)

ROOT_DIR=`echo ${PROJECT_DIR%/build*}`
cd $ROOT_DIR

TOOLCHAIN_DIR=toolchain-arm-linux-gnueabihf-6.3.1

if [ ! -d ./toolchains/$TOOLCHAIN_DIR ]
then
	tar -xzvf ./build/amlogic/$TOOLCHAIN_DIR.tar.gz -C ./toolchains/
fi

CROSS_COMPILE_CHAIN=$ROOT_DIR/toolchains/$TOOLCHAIN_DIR/bin
echo $CROSS_COMPILE_CHAIN
export HOST_CHAIN=arm-linux-gnueabihf
export TARGET_PLATFORM=amlogic
export ROOT_DIR=$ROOT_DIR
echo $HOST_CHAIN
if [[ $PATH != *$CROSS_COMPILE_CHAIN* ]]
then
	export PATH=$CROSS_COMPILE_CHAIN:$PATH
fi

cd $CUR_DIR
