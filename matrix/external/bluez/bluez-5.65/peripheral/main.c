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

uhos_u16 conn_handle = 0x0000;
uhos_ble_addr_t           peer_addr;
uhos_ble_addr_type_t      type;

void uh_ble_gap_callback(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param)
{
	switch(evt)
	{
		case UHOS_BLE_GAP_EVT_CONNECTED:
		{
			uhos_ble_gap_evt_param_t *evt = param;

			LOGW("connected: handle(%04x) role(%02x)", evt->conn_handle, evt->connect.role);
			LOGW("connected: peer_addr(%02x:%02x:%02x:%02x:%02x:%02x) type(%02x)", evt->connect.peer_addr[5], evt->connect.peer_addr[4], 
						evt->connect.peer_addr[3], evt->connect.peer_addr[2],
						evt->connect.peer_addr[1], evt->connect.peer_addr[0],
						evt->connect.type);
			type = evt->connect.type;
			memcpy(peer_addr, evt->connect.peer_addr, 6);
			conn_handle = evt->conn_handle; 
			break;
		}
    	case UHOS_BLE_GAP_EVT_DISCONNET:
		{
			uhos_ble_gap_evt_param_t *evt = param;
			LOGW("disconnected handle(%04x) reason(%02x)", evt->conn_handle, evt->disconnect.reason);
			conn_handle = 0x0000;
			break;
		}
    	case UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED:
		{
			break;
		}
    	case UHOS_BLE_GAP_EVT_ADV_REPORT:
		{
			uhos_ble_gap_adv_report_t * rpt = &param->report;
			LOGW("peer_addr(%02x:%02x:%02x:%02x:%02x:%02x) rssi(%d)", rpt->peer_addr[0], rpt->peer_addr[1], rpt->peer_addr[2],
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
	LOGD("Using Public Address %02x:%02x:%02x:%02x:%02x:%02x\n",
								static_addr[5], static_addr[4], static_addr[3],
								static_addr[2], static_addr[1], static_addr[0]);

	uhos_ble_gap_adv_data_set(ble_adv_data, sizeof(ble_adv_data), ble_scan_rsp, sizeof(ble_scan_rsp));

	uhos_ble_gap_adv_param_t param = {
		.adv_interval_max = 100,
		.adv_interval_min = 100,
		.adv_type = UHOS_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED,
	};

	uhos_ble_gap_adv_start(&param);

	uhos_ble_gap_scan_param_t scan_param = {
		.scan_interval = 0x100,
		.scan_window = 0x100,
		.timeout = 0x00,
	};

	uhos_ble_gap_callback_register(uh_ble_gap_callback);

	uint16_t count = 0;

	while(1)
	{
		sleep(1);
		uhos_s8 rssi = 0;
		uhos_u16 mtu = 0;

		if (conn_handle != 0x0000) {
			count ++;
			uhos_ble_rssi_get(conn_handle, &rssi);
			uhos_ble_gatts_mtu_get(conn_handle, &mtu);
			LOGI("mtu is %d", mtu);
			if (count == 0xFFF) {
				uhos_ble_gap_disconnect(conn_handle);
				count = 0;
			}
		}
	}

	uhos_ble_gap_adv_stop();
	uhos_ble_disable();
	return 0;
}
