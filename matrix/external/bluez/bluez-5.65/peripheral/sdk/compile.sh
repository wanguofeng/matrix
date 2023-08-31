#!/bin/bash

rm -rfv *.o *.a output/

mkdir -v output

ar vx ../../lib/.libs/libbluetooth-internal.a 

ar vx ../../src/.libs/libshared-mainloop.a 

cp -v ../*.o .

rm -v main.o
rm -v libshared_mainloop_la-hfp.o
rm -v libshared_mainloop_la-ad.o
rm -v libshared_mainloop_la-log.o
rm -v libshared_mainloop_la-pcap.o
rm -v libshared_mainloop_la-shell.o
rm -v libshared_mainloop_la-uhid.o

ar crv libbt-bluez-adapter.a *.o

#rm -v *.o

mv -v libbt-bluez-adapter.a output/

cd uhos_ble

gcc main.c ../output/libbt-bluez-adapter.a -lpthread -o uhos_ble
