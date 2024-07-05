#!/bin/bash

#export PATH=$PATH:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

#export STAGING_DIR=$STAGING_DIR:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

#CC="arm-openwrt-linux-gcc"
#AR="arm-openwrt-linux-ar"
#STRIP="arm-openwrt-linux-strip"
#DUMP="arm-openwrt-linux-objdump"

#unset CC
#unset AR
#unset STRIP
#unset DUMP

CC="gcc"
AR="ar"
STRIP="strip"
DUMP="objdump"

rm -rfv *.o *.a *.so *.map *.asm assem_test

$CC test.c -g -o assem_test -Wl,-Map=output.map

$DUMP -d assem_test > test.asm
