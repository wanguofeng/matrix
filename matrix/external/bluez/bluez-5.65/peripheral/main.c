#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "peripheral/uh_ble.h"

#define CONFIG_LOG_TAG	"demo"
#include "peripheral/log.h"

// 定义广播包类型
#define BLE_AD_TYPE_FLAGS                    0x01
#define BLE_AD_TYPE_16BIT_SERVICE_UUID        0x02
#define BLE_AD_TYPE_COMPLETE_LOCAL_NAME      0x09

// 定义服务UUID
#define BLE_SERVICE_UUID                     0x180D

void uh_ble_gap_callback(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param)
{
	switch(evt)
	{
		case UHOS_BLE_GAP_EVT_CONNECTED:
		{
			uhos_ble_gap_connect_t *t = &param->connect;
			LOGE("connected");
			break;
		}
    	case UHOS_BLE_GAP_EVT_DISCONNET:
		{
			break;
		}
    	case UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED:
		{
			break;
		}
    	case UHOS_BLE_GAP_EVT_ADV_REPORT:
		{
			uhos_ble_gap_adv_report_t * rpt = &param->report;
			LOGE("peer addr(%02x:%02x:%02x:%02x:%02x:%02x) rssi(%d)", rpt->peer_addr[0], rpt->peer_addr[1], rpt->peer_addr[2],
													rpt->peer_addr[3], rpt->peer_addr[4], rpt->peer_addr[5], rpt->rssi);
			break;
		}
	}
}

// 构造广播数据
const uint8_t ble_adv_data[] = {
	// // 广播包类型：Flags
	// 0x02, BLE_AD_TYPE_FLAGS, 0x06, // 0000 0110

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

int main(int argc, char *argv[])
{
	uhos_ble_enable();
	uhos_u8 static_addr[6] = {0x00};
	uhos_ble_address_get(static_addr);
	LOGD("Using static address %02x:%02x:%02x:%02x:%02x:%02x\n",
								static_addr[5], static_addr[4], static_addr[3],
								static_addr[2], static_addr[1], static_addr[0]);

	uhos_ble_gap_adv_data_set(ble_adv_data, sizeof(ble_adv_data), ble_scan_rsp, sizeof(ble_scan_rsp));

	uhos_ble_gap_adv_param_t param = {
		.adv_interval_max = 0x100,
		.adv_interval_min = 0x100,
		.adv_type = UHOS_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED,
	};

	uhos_ble_gap_adv_start(&param);

	uhos_ble_gap_scan_param_t scan_param = {
		.scan_interval = 0x100,
		.scan_window = 0x100,
		.timeout = 0x00,
	};

	uhos_ble_gap_callback_register(uh_ble_gap_callback);

	while(1)
	{
		sleep(10);
		// uhos_ble_gap_scan_start(UHOS_BLE_SCAN_TYPE_ACTIVE, scan_param);
		// sleep(10);
		// uhos_ble_gap_scan_stop();
	}

	uhos_ble_gap_adv_stop();
	uhos_ble_disable();
	return 0;
}
