// SPDX-License-Identifier: LGPL-2.1-or-later

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#include "src/shared/mainloop.h"
// #include "src/shared/util.h"
// #include "lib/bluetooth.h"
#include "monitor/bt.h"
#include "peripheral/uh_ble.h"
#include "peripheral/adv.h"

extern void * bluez_gatt_daemon(void *arg);

static pthread_t bluez_daemon_tid = (pthread_t)0;
static void stack_gap_event_callback(uint16_t event, const void *data, uint8_t size, void *user_data);
/*
 * BLE COMMON
*/
uhos_ble_status_t uhos_ble_enable(void)
{
    int ret = 0;

    if (bluez_daemon_tid != (pthread_t)0) {
        printf("bluez daemon is already init\n");
        return UHOS_BLE_ERROR;
    }
    
    // sem_t bluez_sem;
	// sem_init(&bluez_sem, 0, 0);
    
    uint16_t hci_index = 1;

    ret = pthread_create(&bluez_daemon_tid, NULL, bluez_daemon, &hci_index);
    if (ret != 0) {
        printf("Error creating thread!\n");
        return UHOS_BLE_ERROR;
    }

    // sem_wait(&bluez_sem);
    // sem_destroy(&bluez_sem);
    
    bluez_register_gap_event_callback(stack_gap_event_callback);
    
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_disable(void)
{
    if (bluez_daemon_tid == (pthread_t)0) {
        printf("bluez daemon isn't inited yet!\n");
        return UHOS_BLE_ERROR;
    }

    pthread_kill(bluez_daemon_tid, SIGTERM);
    pthread_join(bluez_daemon_tid, NULL);
    bluez_daemon_tid = (pthread_t)0;

    printf("bluez daemon exit successfully\n");

    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_address_get(uhos_ble_addr_t mac)
{   
    bluez_get_bd_addr((uint8_t * )mac);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_start(uhos_u16 conn_handle)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_get_detect(uhos_u16 conn_handle, uhos_s8 *rssi)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_get(uhos_u16 conn_handle, uhos_s8 *rssi)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_stop(uhos_u16 conn_handle)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_tx_power_set(uhos_u16 conn_handle, uhos_s8 tx_power)
{

    return UHOS_BLE_SUCCESS;
}

/*
 * BLE GAP
*/
#define UHOS_BLE_GAP_MAX_USERS              4
uhos_ble_gap_cb_t   g_uhos_ble_pal_gap_cb_table[UHOS_BLE_GAP_MAX_USERS] = { NULL };
uhos_u8             g_gap_users = 0;

static uhos_ble_status_t uhos_ble_gap_callback(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param)
{
    int i = 0;
    uhos_ble_gap_cb_t cb = UHOS_NULL;
    while (i < g_gap_users) {
        if (g_uhos_ble_pal_gap_cb_table[i] != UHOS_NULL) {
            cb = g_uhos_ble_pal_gap_cb_table[i];
            cb(evt, param);
        }
        i++; 
    }
}

uhos_ble_status_t uhos_ble_gap_callback_register(uhos_ble_gap_cb_t cb)
{
    int i = 0;
    while (i < UHOS_BLE_GAP_MAX_USERS) {
        if (g_uhos_ble_pal_gap_cb_table[i] == UHOS_NULL) {
            g_uhos_ble_pal_gap_cb_table[i] = cb;
            g_gap_users ++;
            return UHOS_BLE_SUCCESS;
        }
        i++;
   }
   return UHOS_BLE_ERROR;  // full
}

static void print_adv_event_type(const char *label, uint8_t type)
{
	const char *str;

	switch (type) {
	case 0x00:
		str = "Connectable undirected - ADV_IND";
		break;
	case 0x01:
		str = "Connectable directed - ADV_DIRECT_IND";
		break;
	case 0x02:
		str = "Scannable undirected - ADV_SCAN_IND";
		break;
	case 0x03:
		str = "Non connectable undirected - ADV_NONCONN_IND";
		break;
	case 0x04:
		str = "Scan response - SCAN_RSP";
		break;
	default:
		str = "Reserved";
		break;
	}
    printf("%s adv event type = %s\n", label, str);
}

static void print_role(uint8_t role)
{
	const char *str;

	switch (role) {
	case 0x00:
		str = "Central";
		break;
	case 0x01:
		str = "Peripheral";
		break;
	default:
		str = "Reserved";
		break;
	}

	printf("Role: %s (0x%2.2x)\n", str, role);
}

static void stack_gap_event_callback(uint16_t event, const void *data, uint8_t size, void *user_data)
{
    switch(event)
    {
        case BT_HCI_EVT_DISCONNECT_COMPLETE:
        {
            const struct bt_hci_evt_disconnect_complete * evt = (data);
	        printf("disconnet event: status = %d, handle = %d, reason = %02x\n",evt->status, evt->handle, evt->reason);

            if (evt->status != 0x00) {
                return;
            }

            uhos_ble_gap_evt_param_t param = {0x00};
            param.conn_handle = evt->handle;
            param.disconnect.reason = evt->reason;

            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_DISCONNET, &param);
            break;
        }
        case BT_HCI_EVT_LE_META_EVENT:
        {
            int8_t evt_code = ((const uint8_t *) data)[0];
	
            switch (evt_code) {
                case BT_HCI_EVT_LE_ADV_REPORT:
                {
                    const struct bt_hci_evt_le_adv_report *evt = (data + 1);
                    
                    // print_adv_event_type("debug:", evt->event_type);
                    // printf("addr_type = %02x, addr = %02x:%02x:%02x:%02x:%02x:%02x, rssi = %d\n", evt->addr_type, 
                    //                 evt->addr[5], evt->addr[4], evt->addr[3], evt->addr[2], evt->addr[1], evt->addr[0], (int8_t)evt->data[evt->data_len]);
    
                    uhos_ble_gap_evt_param_t param = {0x00};
                    param.conn_handle = 0x00; // not valiable

                    if (evt->addr_type == 0x00)
                        param.report.addr_type = UHOS_BLE_ADDRESS_TYPE_PUBLIC;
                    else
                        param.report.addr_type = UHOS_BLE_ADDRESS_TYPE_RANDOM;

                    if (evt->event_type == 0x04)
                        param.report.adv_type = SCAN_RSP_DATA;
                    else
                        param.report.adv_type = ADV_DATA;
                    
                    memcpy(param.report.data, evt->data, evt->data_len);
                    memcpy(param.report.peer_addr, evt->addr, 6);
                    param.report.rssi = (int8_t)evt->data[evt->data_len];

                    uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_ADV_REPORT, &param);
                    break;
                }
            
                case BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE:
                {
                    const struct bt_hci_evt_le_enhanced_conn_complete * evt = (data + 1);
                    
                    printf("connected event: status = %02x, handle = %02x, peer_addr_type = %02x\n",
                                                    evt->status, evt->handle, evt->peer_addr_type);
                    printf("connected event: peer_addr = %02x:%02x:%02x:%02x:%02x:%02x\n", 
                            evt->peer_addr[0], evt->peer_addr[1], evt->peer_addr[2], evt->peer_addr[3], evt->peer_addr[4], evt->peer_addr[5]);
                    print_role(evt->role);
                    
                    uhos_ble_gap_evt_param_t param = {0x00};

                    if (evt->role == 0x00)
                        param.connect.role = UHOS_BLE_GAP_CENTRAL;
                    else
                        param.connect.role = UHOS_BLE_GAP_PERIPHERAL;

                    param.connect.type = evt->peer_addr_type;
                    param.conn_handle = evt->handle;
                    param.connect.conn_param.conn_sup_timeout = evt->supv_timeout;
                    param.connect.conn_param.max_conn_interval = evt->interval;
                    param.connect.conn_param.min_conn_interval = evt->interval;
                    param.connect.conn_param.slave_latency = evt->latency;
                    memcpy(param.connect.peer_addr, evt->peer_addr, 6);
                    
                    uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_CONNECTED, &param);
                    break;
                }
                case BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE:
                {
                    const struct bt_hci_evt_le_conn_update_complete * evt = (data + 1);
                    printf("conn_update event: status = %02x, handle = %02x, interval = %02x, latency = %02x, supv_timeout = %02x\n",
                                        evt->status, evt->handle, evt->interval, evt->latency, evt->supv_timeout);
                    
                    uhos_ble_gap_evt_param_t param = {0x00};
                    param.conn_handle = evt->handle;
                    param.update_conn.conn_param.conn_sup_timeout = evt->supv_timeout;
                    param.update_conn.conn_param.max_conn_interval = evt->interval;
                    param.update_conn.conn_param.min_conn_interval = evt->interval;
                    param.update_conn.conn_param.slave_latency = evt->latency;

                    uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED, &param);
                    break;
                }
            }
            break;
        } 
    }
}

uhos_ble_status_t uhos_ble_gap_adv_data_set(
    uhos_u8 const *p_data, 
    uhos_u8 dlen,
    uhos_u8 const *p_sr_data,
    uhos_u8 srdlen)
{
    bluez_set_adv_data(p_data, dlen, p_sr_data, srdlen);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_adv_start(uhos_ble_gap_adv_param_t *p_adv_param)
{
    uint8_t ch_mask = 0x07;

    if (p_adv_param->ch_mask.ch_37_off) {
        ch_mask &= ~ 0x01;
    }

    if (p_adv_param->ch_mask.ch_38_off) {
        ch_mask &= ~ 0x02;
    }

    if (p_adv_param->ch_mask.ch_39_off) {
        ch_mask &= ~ 0x04;
    }

    bluez_set_adv_param(p_adv_param->adv_interval_min, p_adv_param->adv_interval_max, 
						p_adv_param->adv_type, p_adv_param->direct_addr_type,
                        ch_mask);

    bluez_set_adv_start(1);
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_reset_adv_start(void)
{
    bluez_set_adv_start(0);
    bluez_set_adv_start(1);
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_adv_stop(void)
{
    bluez_set_adv_start(0);
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_scan_start(
    uhos_ble_gap_scan_type_t scan_type,
    uhos_ble_gap_scan_param_t scan_param)
{
    bluez_set_scan_param(scan_type, scan_param.scan_interval, scan_param.scan_window);
    bluez_set_scan_enable(1);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_scan_stop(void)
{
    bluez_set_scan_enable(0);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_update_conn_params(
    uhos_u16 conn_handle,
    uhos_ble_gap_conn_param_t conn_params)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_disconnect(uhos_u16 conn_handle)
{
    bluez_set_gap_disconnect(conn_handle);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_connect(uhos_ble_gap_scan_param_t scan_param,
                                              uhos_ble_gap_connect_t conn_param)
{
    uint8_t addr_type = 0;
    uint8_t own_address_type = 0;

    if (conn_param.type == UHOS_BLE_ADDRESS_TYPE_PUBLIC)
        addr_type = 0x00;
    else
        addr_type = 0x01;;

    own_address_type = 0x00; // public devices address;

    bluez_set_gap_connect(scan_param.scan_interval, scan_param.scan_window,
                addr_type, conn_param.peer_addr, own_address_type,
                conn_param.conn_param.min_conn_interval, conn_param.conn_param.max_conn_interval,
                conn_param.conn_param.slave_latency, conn_param.conn_param.conn_sup_timeout);

    return UHOS_BLE_SUCCESS;
}

/**************************************************************************************************/
/* BLE GATT层server相关功能接口原型                                                               */
/**************************************************************************************************/
uhos_ble_status_t uhos_ble_gatts_callback_register(uhos_ble_gatts_cb_t cb)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_service_set(uhos_ble_gatts_db_t *service_database)
{
    uhos_ble_gatts_srv_db_t     *p_srv_db;
    uhos_u8                     srv_num;
    uhos_ble_status_t           status;
    srv_num = service_database->srv_num;

    if (srv_num == 0 || srv_num >= 10) {
        printf("srv num limited, num = %d\n", srv_num);
        return UHOS_BLE_ERROR;
    }

    for (int i = 0; i < srv_num; i ++) {
        p_srv_db = &service_database->p_srv_db[i];
        // status  = bluez_gatts_add_service(p_srv_db);
        if (UHOS_BLE_SUCCESS != status) {
            printf("ble add service failed %d\n", i);
            continue;
        }
    }

    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_notify_or_indicate(
    uhos_u16 conn_handle,
    uhos_u16 srv_handle,
    uhos_u16 char_value_handle,
    uhos_u8 offset,
    uhos_u8 *p_value,
    uhos_u16 len)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_mtu_default_set(uhos_u16 mtu)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_mtu_get(uhos_u16 conn_handle, uhos_u16 *mtu_size)
{
    return UHOS_BLE_SUCCESS;
}

/**************************************************************************************************/
/* BLE GATT层client相关功能接口原型                                                               */
/**************************************************************************************************/
uhos_ble_status_t uhos_ble_gattc_callback_register(uhos_ble_gattc_callback_t cb)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_primary_service_discover_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_srv_uuid)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_char_discover_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_char_uuid)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_clt_cfg_descriptor_discover(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_read_char_value_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_char_uuid)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_write_with_rsp(
    uhos_u16 conn_handle,
    uhos_u16 handle,
    uhos_u8 *p_value,
    uhos_u8 len)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_write_cmd(
    uhos_u16 conn_handle,
    uhos_u16 handle,
    uhos_u8 *p_value,
    uhos_u8 len)
{
    return UHOS_BLE_SUCCESS;
}
