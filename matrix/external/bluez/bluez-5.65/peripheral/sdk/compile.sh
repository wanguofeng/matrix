#!/bin/bash

rm -rfv *.o *.a output/

mkdir -v output

ar vx ../../lib/.libs/libbluetooth-internal.a 

ar vx ../../src/.libs/libshared-mainloop.a 

cp -v ../*.o .
rm -v main.o

ar crv libbt-adapter.a *.o

rm -v *.o

mv -v libbt-adapter.a output/

cd uhos_ble

gcc main.c ../output/libbt-adapter.a -lpthread -o uhos_ble
