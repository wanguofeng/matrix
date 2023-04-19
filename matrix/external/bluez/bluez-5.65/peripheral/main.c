#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "peripheral/uh_ble.h"

// 定义广播包类型
#define BLE_AD_TYPE_FLAGS                    0x01
#define BLE_AD_TYPE_16BIT_SERVICE_UUID        0x02
#define BLE_AD_TYPE_COMPLETE_LOCAL_NAME      0x09

// 定义服务UUID
#define BLE_SERVICE_UUID                     0x180D

// 定义设备名称
#define BLE_DEVICE_NAME                      "My Device"


int main(int argc, char *argv[])
{
	uhos_u8 static_addr[6] = {0x00};

	uhos_ble_enable();
	
	sleep(5);

	uhos_ble_address_get(static_addr);

	printf("Using static address %02x:%02x:%02x:%02x:%02x:%02x\n",
		static_addr[5], static_addr[4], static_addr[3],
		static_addr[2], static_addr[1], static_addr[0]);

	// 构造广播数据
	const uint8_t ble_adv_data[] = {
		// 广播包类型：Flags
		0x02, BLE_AD_TYPE_FLAGS, 0x06, // 0000 0110
	
		// 广播包类型：Service UUIDs
		0x03, BLE_AD_TYPE_16BIT_SERVICE_UUID, 
		(BLE_SERVICE_UUID & 0xFF), ((BLE_SERVICE_UUID >> 8) & 0xFF),
	
		// 广播包类型：Complete Local Name
		0x07, BLE_AD_TYPE_COMPLETE_LOCAL_NAME, 'w', 'a', 'n', 'w', 'a', 'n'
	};

	// 构造扫描响应数据
	const uint8_t ble_scan_rsp[] = {
		// 广播包类型：Complete Local Name
		0x07, BLE_AD_TYPE_COMPLETE_LOCAL_NAME, 'w', 'a', 'n', 'w', 'a', 'n'
	};

	uhos_ble_gap_adv_data_set(ble_adv_data, sizeof(ble_adv_data), ble_scan_rsp, sizeof(ble_scan_rsp));

	uhos_ble_gap_adv_param_t adv_param = {
		.adv_interval_max = 0x100,
		.adv_interval_min = 0x100,
		.adv_type = UHOS_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED,
		.direct_addr_type = UHOS_BLE_ADDRESS_TYPE_PUBLIC,
		.ch_mask.ch_37_off = 0x00,
		.ch_mask.ch_38_off = 0x00,
		.ch_mask.ch_39_off = 0x00,
	};

	uhos_ble_gap_adv_start(&adv_param);
	
   	uhos_ble_gap_scan_type_t scan_type = UHOS_BLE_SCAN_TYPE_ACTIVE;
    uhos_ble_gap_scan_param_t scan_param = {
		.scan_interval = 0x20,
		.scan_window = 0x20,
    	.timeout = 0x00,
	};

	// uhos_ble_gap_scan_start(scan_type, scan_param);
	
	while(1)
	{

	}

	// uhos_ble_gap_scan_stop();
	uhos_ble_gap_adv_stop();
	uhos_ble_disable();

	return 0;
}