#!/bin/bash

export PATH=$PATH:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

export STAGING_DIR=$STAGING_DIR:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

CC="arm-openwrt-linux-gcc"
AR="arm-openwrt-linux-ar"

#unset CC
#unset AR
#CC="gcc"
#AR="ar"

rm -rfv *.o *.a *.so

# static library
$CC -c ../lib/bluetooth.c -g -o bluetooth.o
$CC -c ../lib/hci.c -g -o hci.o
$CC -c ../lib/sdp.c -g -o sdp.o -I ../lib
$CC -c ../lib/uuid.c -g -o uuid.o -I ../

$CC -c ../src/shared/queue.c -g -o queue.o -I ../
$CC -c ../src/shared/util.c -g -o util.o -I ../
$CC -c ../src/shared/mgmt.c -g -o mgmt.o -I ../
$CC -c ../src/shared/crypto.c -g -o crypto.o -I ../
$CC -c ../src/shared/ecc.c -g -o ecc.o -I ../
$CC -c ../src/shared/ringbuf.c -g -o ringbuf.o -I ../
$CC -c ../src/shared/hci.c -g -o shared-hci.o -I ../
$CC -c ../src/shared/hci-crypto.c -g -o hci-crypto.o -I ../
# $CC -c ../src/shared/ad.c -g -o ad.o -I ../
$CC -c ../src/shared/att.c -g -o att.o -I ../
$CC -c ../src/shared/gatt-helpers.c -g -o gatt-helpers.o -I ../
$CC -c ../src/shared/gatt-client.c -g -o gatt-client.o -I ../
$CC -c ../src/shared/gatt-server.c -g -o gatt-server.o -I ../
$CC -c ../src/shared/gatt-db.c -g -o gatt-db.o -I ../
$CC -c ../src/shared/gap.c -g -o gap.o -I ../
$CC -c ../src/shared/io-mainloop.c -g -o io-mainloop.o -I ../
$CC -c ../src/shared/timeout-mainloop.c -g -o timeout-mainloop.o -I ../
$CC -c ../src/shared/mainloop.c -g -o mainloop.o -I ../
$CC -c ../src/shared/mainloop-notify.c -g -o mainloop-notify.o -I ../
 
$CC -c ../peripheral/gap.c -g -o peripheral-gap.o -I ../peripheral/ -I ../
$CC -c ../peripheral/gatt.c -g -o peripheral-gatt.o -I ../peripheral/ -I ../
$CC -c ../peripheral/uh_ble.c -g -o peripheral-uh_ble.o -I ../peripheral/ -I ../
$CC -c ../peripheral/utils.c -g -o peripheral-utils.o  -I ../peripheral/ -I ../
$CC -c ../peripheral/conn_info.c -g -o peripheral-conn_info.o -I ../peripheral/ -I ../

$AR crv libbt-bluez-adapter.a *.o

$CC ../peripheral/main.c -o bt_test -L. -lbt-bluez-adapter -I ../peripheral -I ../ -D VERSION="5.54"

# shared library
#$CC -c -fPIC ../lib/bluetooth.c -o bluetooth.o
#$CC -c -fPIC ../lib/hci.c -o hci.o
#$CC -c -fPIC ../lib/sdp.c -o sdp.o -I ../lib
#$CC -c -fPIC ../lib/uuid.c -o uuid.o -I ../

#$CC -c -fPIC ../src/shared/queue.c -o queue.o -I ../
#$CC -c -fPIC ../src/shared/util.c -o util.o -I ../
#$CC -c -fPIC ../src/shared/mgmt.c -o mgmt.o -I ../
#$CC -c -fPIC ../src/shared/crypto.c -o crypto.o -I ../
#$CC -c -fPIC ../src/shared/ecc.c -o ecc.o -I ../
#$CC -c -fPIC ../src/shared/ringbuf.c -o ringbuf.o -I ../
#$CC -c -fPIC ../src/shared/hci.c -o hci.o -I ../
#$CC -c -fPIC ../src/shared/hci-crypto.c -o hci-crypto.o -I ../
# $CC -c -fPIC ../src/shared/ad.c -o ad.o -I ../
#$CC -c -fPIC ../src/shared/att.c -o att.o -I ../
#$CC -c -fPIC ../src/shared/gatt-helpers.c -o gatt-helpers.o -I ../
#$CC -c -fPIC ../src/shared/gatt-client.c -o gatt-client.o -I ../
#$CC -c -fPIC ../src/shared/gatt-server.c -o gatt-server.o -I ../
#$CC -c -fPIC ../src/shared/gatt-db.c -o gatt-db.o -I ../
#$CC -c -fPIC ../src/shared/gap.c -o gap.o -I ../
#$CC -c -fPIC ../src/shared/io-mainloop.c -o io-mainloop.o -I ../
#$CC -c -fPIC ../src/shared/timeout-mainloop.c -o timeout-mainloop.o -I ../
#$CC -c -fPIC ../src/shared/mainloop.c -o mainloop.o -I ../
#$CC -c -fPIC ../src/shared/mainloop-notify.c -o mainloop-notify.o -I ../
 
#$CC -c -fPIC ../peripheral/gap.c -o peripheral-gap.o -I ../peripheral/ -I ../
#$CC -c -fPIC ../peripheral/gatt.c -o peripheral-gatt.o -I ../peripheral/ -I ../
#$CC -c -fPIC ../peripheral/uh_ble.c -o peripheral-uh_ble.o -I ../peripheral/ -I ../
#$CC -c -fPIC ../peripheral/utils.c -o peripheral-utils.o  -I ../peripheral/ -I ../
#$CC -c -fPIC ../peripheral/conn_info.c -o peripheral-conn_info.o -I ../peripheral/ -I ../

#$CC -shared -fPIC -o libbt-bluez-adapter.so *.o

