#/bin/bash
cp CMakeLists_cross_compile.txt CMakeLists.txt
cmake .
make
/home/wanguofeng/Workspace/miio_bt_platform2/miio_bt_builder/toolchains/toolchain-arm-linux-gnueabihf-6.3.1/bin/arm-linux-gnueabihf-gcc xiaomi.c -I. -L. -lunqlite -o parse_unqlite
/home/wanguofeng/Workspace/miio_bt_platform2/miio_bt_builder/toolchains/toolchain-arm-linux-gnueabihf-6.3.1/bin/arm-linux-gnueabihf-gcc create_unqlite.c -I. -L. -lunqlite -o create_unqlite
