#!/bin/bash

export PATH=$PATH:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

export STAGING_DIR=$STAGING_DIR:/home/guofeng/Workspace/myself/matrix/matrix/toolchains/r328-toolchain/toolchain-sunxi-musl/toolchain/bin

CC="arm-openwrt-linux-gcc"
AR="arm-openwrt-linux-ar"

unset CC
unset AR
CC="gcc"
AR="ar"

rm -rfv *.o *.a *.so bt_test

# static library
$CC -c   ../lib/bluetooth.c -g -o bluetooth.o
$CC -c   ../lib/hci.c -g -o hci.o
$CC -c   ../lib/sdp.c -g -o sdp.o -I ../lib
$CC -c   ../lib/uuid.c -g -o uuid.o -I ../

$CC -c   ../src/shared/queue.c -g -o queue.o -I ../
$CC -c   ../src/shared/util.c -g -o util.o -I ../
$CC -c   ../src/shared/mgmt.c -g -o mgmt.o -I ../
$CC -c   ../src/shared/crypto.c -g -o crypto.o -I ../
$CC -c   ../src/shared/ecc.c -g -o ecc.o -I ../
$CC -c   ../src/shared/ringbuf.c -g -o ringbuf.o -I ../
$CC -c   ../src/shared/hci.c -g -o shared-hci.o -I ../
$CC -c   ../src/shared/hci-crypto.c -g -o hci-crypto.o -I ../
# $CC -c   ../src/shared/ad.c -g -o ad.o -I ../
$CC -c   ../src/shared/att.c -g -o att.o -I ../
$CC -c   ../src/shared/gatt-helpers.c -g -o gatt-helpers.o -I ../
$CC -c   ../src/shared/gatt-client.c -g -o gatt-client.o -I ../
$CC -c   ../src/shared/gatt-server.c -g -o gatt-server.o -I ../
$CC -c   ../src/shared/gatt-db.c -g -o gatt-db.o -I ../
$CC -c   ../src/shared/gap.c -g -o gap.o -I ../
$CC -c   ../src/shared/io-mainloop.c -g -o io-mainloop.o -I ../
$CC -c   ../src/shared/timeout-mainloop.c -g -o timeout-mainloop.o -I ../
$CC -c   ../src/shared/mainloop.c -g -o mainloop.o -I ../
$CC -c   ../src/shared/mainloop-notify.c -g -o mainloop-notify.o -I ../
 
$CC -c   ../peripheral/gap-mgmt.c -g -o peripheral-gap-mgmt.o -I ../peripheral/ -I ../
$CC -c   ../peripheral/gatt.c -g -o peripheral-gatt.o -I ../peripheral/ -I ../
$CC -c   ../peripheral/uh_ble.c -g -o peripheral-uh_ble.o -I ../peripheral/ -I ../
$CC -c   ../peripheral/utils.c -g -o peripheral-utils.o  -I ../peripheral/ -I ../
$CC -c   ../peripheral/conn_info.c -g -o peripheral-conn_info.o -I ../peripheral/ -I ../

echo "***************************** Generate static library *****************************"
$AR crv libbt-bluez-adapter.a *.o

echo "***************************** Generate bt_test ************************************"
$CC ../peripheral/main.c -o bt_test -L. -lbt-bluez-adapter -lpthread -I ../peripheral -I ../

# shared library

rm -rfv *.o *.so

$CC -c -fPIC ../lib/bluetooth.c -g -o bluetooth.o
$CC -c -fPIC ../lib/hci.c -g -o hci.o
$CC -c -fPIC ../lib/sdp.c -g -o sdp.o -I ../lib
$CC -c -fPIC ../lib/uuid.c -g -o uuid.o -I ../

$CC -c -fPIC ../src/shared/queue.c -g -o queue.o -I ../
$CC -c -fPIC ../src/shared/util.c -g -o util.o -I ../
$CC -c -fPIC ../src/shared/mgmt.c -g -o mgmt.o -I ../
$CC -c -fPIC ../src/shared/crypto.c -g -o crypto.o -I ../
$CC -c -fPIC ../src/shared/ecc.c -g -o ecc.o -I ../
$CC -c -fPIC ../src/shared/ringbuf.c -g -o ringbuf.o -I ../
$CC -c -fPIC ../src/shared/hci.c -g -o shared-hci.o -I ../
$CC -c -fPIC ../src/shared/hci-crypto.c -g -o hci-crypto.o -I ../
# $CC -c -fPIC ../src/shared/ad.c -g -o ad.o -I ../
$CC -c -fPIC ../src/shared/att.c -g -o att.o -I ../
$CC -c -fPIC ../src/shared/gatt-helpers.c -g -o gatt-helpers.o -I ../
$CC -c -fPIC ../src/shared/gatt-client.c -g -o gatt-client.o -I ../
$CC -c -fPIC ../src/shared/gatt-server.c -g -o gatt-server.o -I ../
$CC -c -fPIC ../src/shared/gatt-db.c -g -o gatt-db.o -I ../
$CC -c -fPIC ../src/shared/gap.c -g -o gap.o -I ../
$CC -c -fPIC ../src/shared/io-mainloop.c -g -o io-mainloop.o -I ../
$CC -c -fPIC ../src/shared/timeout-mainloop.c -g -o timeout-mainloop.o -I ../
$CC -c -fPIC ../src/shared/mainloop.c -g -o mainloop.o -I ../
$CC -c -fPIC ../src/shared/mainloop-notify.c -g -o mainloop-notify.o -I ../
 
$CC -c -fPIC ../peripheral/gap-mgmt.c -g -o peripheral-gap-mgmt.o -I ../peripheral/ -I ../
$CC -c -fPIC ../peripheral/gatt.c -g -o peripheral-gatt.o -I ../peripheral/ -I ../
$CC -c -fPIC ../peripheral/uh_ble.c -g -o peripheral-uh_ble.o -I ../peripheral/ -I ../
$CC -c -fPIC ../peripheral/utils.c -g -o peripheral-utils.o  -I ../peripheral/ -I ../
$CC -c -fPIC ../peripheral/conn_info.c -g -o peripheral-conn_info.o -I ../peripheral/ -I ../

echo "****************************** Generate share library ******************************"
$CC -shared -fPIC -o libbt-bluez-adapter.so *.o

