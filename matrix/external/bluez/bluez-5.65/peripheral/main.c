#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "peripheral/uh_ble.h"

int main(int argc, char *argv[])
{
	uhos_ble_enable();
	uhos_u8 static_addr[6] = {0x00};
	sleep(5);
	uhos_ble_address_get(static_addr);
	printf("Using static address %02x:%02x:%02x:%02x:%02x:%02x\n",
		static_addr[5], static_addr[4], static_addr[3],
		static_addr[2], static_addr[1], static_addr[0]);
	uhos_ble_disable();

	return 0;
}
