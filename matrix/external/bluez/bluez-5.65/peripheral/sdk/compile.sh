#!/bin/bash

rm -rfv *.o *.a output/

mkdir -v output

ar vx ../../lib/.libs/libbluetooth-internal.a 

ar vx ../../src/.libs/libshared-mainloop.a 

cp -v ../*.o .
rm -v main.o

ar crv libbt-bluez-adapter.a *.o

rm -v *.o

mv -v libbt-bluez-adapter.a output/

cd uhos_ble

gcc main.c ../output/libbt-bluez-adapter.a -lpthread -o uhos_ble
