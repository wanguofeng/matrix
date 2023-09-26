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

#include "src/shared/mgmt.h"

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "peripheral/gap.h"
#include "peripheral/gatt.h"

#include "peripheral/uh_ble.h"
#include "peripheral/conn_info.h" 
#include "peripheral/utils.h"

#define CONFIG_LOG_TAG "Bluez_Adapter"
#include "peripheral/log.h"

// #define Bluez_Adapter_Version     "v1.0.14-alpha-202305121355"

#define Bluez_Adapter_Version     "v1.0.30-rc-20230925"
// #define Bluez_Adapter_Version     "v1.1.0-rc"
// #define Bluez_Adapter_Version     "v1.1.0-release"

/*
 * BLE COMMON
*/

static uhos_ble_status_t uhos_ble_gap_callback(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param);
static uhos_ble_status_t uhos_ble_gatts_callback(uhos_ble_gatts_evt_t evt, uhos_ble_gatts_evt_param_t *param);
static pthread_t bluez_daemon_tid = (pthread_t)0;
static sem_t bluez_adapter_sem;

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	case SIGCHLD:
		break;
	}
}

#define VERSION "5.65"

static void * bluez_daemon(void *arg)
{
    int exit_status = 0;
    uint16_t hci_index = *(uint16_t *) arg;

    LOGW("Bluetooth periperhal ver %s, hci_index = %d", VERSION, hci_index);
    LOGW("Bluetooth Adapter Version %s", Bluez_Adapter_Version);

	mainloop_init();
	bluez_gap_init();
    bluez_gap_adapter_init(hci_index);

    exit_status = mainloop_run();

    LOGI("bluez daemon exit_status(%d)", exit_status);

	bluez_gap_uinit();
    bluez_gatts_server_stop();

    pthread_exit(NULL);
}

static void stack_gap_event_callback(uint16_t event, uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
    switch(event)
    {
        case MGMT_EV_DEVICE_CONNECTED:
        {
            const struct mgmt_ev_device_connected *ev = param;
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            
            struct addr_info bdaddr;

            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            uint8_t role = conn_info_get_role_by_addr(bdaddr);
            evt_param.conn_handle = conn_info_generate_handle();
            evt_param.connect.role = role;

            LOGI("connected handle = %04x", evt_param.conn_handle);

            if (ev->addr.type == BDADDR_LE_PUBLIC) {
                evt_param.connect.type = UHOS_BLE_ADDRESS_TYPE_PUBLIC;
            } else if (ev->addr.type == BDADDR_LE_RANDOM) {
                evt_param.connect.type = UHOS_BLE_ADDRESS_TYPE_RANDOM;
            } else {
                evt_param.connect.type = 0x02; // unknow;
            }

            memcpy(evt_param.connect.peer_addr, ev->addr.bdaddr.b, 6);

            evt_param.connect.conn_param.conn_sup_timeout = 0x00; // can't get this param;
            evt_param.connect.conn_param.max_conn_interval = 0x00; // can't get this param;
            evt_param.connect.conn_param.min_conn_interval = 0x00; // can't get this param;
            evt_param.connect.conn_param.slave_latency = 0x00; // can't get this param;

            conn_info_add_gatts(evt_param.conn_handle, bdaddr);
            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_CONNECTED, &evt_param);
            break;
        }   
        case MGMT_EV_DEVICE_DISCONNECTED:
        {
            const struct mgmt_ev_device_disconnected *ev = param;

            uhos_ble_gap_evt_param_t evt_param = {0x00};

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);

            uint8_t reason = UNKNOW_OTHER_ERROR;

            if (ev->reason == MGMT_DEV_DISCONN_REMOTE) {
                reason = UHOS_BLE_REMOTE_USER_TERMINATED;
            } else if (ev->reason == MGMT_DEV_DISCONN_TIMEOUT) {
                reason = UHOS_BLE_CONNECTION_TIMEOUT;
            } else if (ev->reason == MGMT_DEV_DISCONN_LOCAL_HOST) {
                reason = UHOS_BLE_LOCAL_HOST_TERMINATED;
            } else {
                reason = UNKNOW_OTHER_ERROR;
            }

            LOGE("disconnect handle = %04x", evt_param.conn_handle);

            evt_param.disconnect.reason = reason;
            conn_info_del_gatts(evt_param.conn_handle, bdaddr);
            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_DISCONNET, &evt_param);
            break;
        }
        case MGMT_EV_NEW_CONN_PARAM:
        {
            const struct mgmt_ev_new_conn_param * ev = param;
            uhos_ble_gap_evt_param_t evt_param = {0x00};

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);
            evt_param.update_conn.conn_param.conn_sup_timeout = ev->timeout;
            evt_param.update_conn.conn_param.max_conn_interval = ev->max_interval;
            evt_param.update_conn.conn_param.min_conn_interval = ev->min_interval;
            evt_param.update_conn.conn_param.slave_latency = ev->latency;
            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED, &evt_param);
            break;
        }
        case MGMT_EV_DEVICE_FOUND:
        {
            const struct mgmt_ev_device_found * ev = param;
            uint16_t eir_len;
            uint32_t flags;
            if (length < sizeof(*ev)) {
                LOGE("Too short device_found length (%u bytes)", length);
                return;
            }
            LOGI("adv data len(%d)", ev->eir_len);
            if (ev->eir_len > 31) {
                LOGI("len(%d) can't process yet", ev->eir_len);
                return;
            }
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            evt_param.conn_handle = 0x00; // not used
            evt_param.report.addr_type = ev->addr.type;
            evt_param.report.adv_type = FULL_DATA; // can't get adv type(refers PDU Type)
            evt_param.report.data_len = ev->eir_len;
            memcpy(evt_param.report.peer_addr, ev->addr.bdaddr.b, 6);
            evt_param.report.rssi = ev->rssi;;
            memcpy(evt_param.report.data, ev->eir, ev->eir_len);
            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_ADV_REPORT, &evt_param);
            break;
        }
    }
}

static void stack_gap_cmd_callback(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data)
{
    switch(cmd)
    {
        case MGMT_OP_READ_DEF_SYSTEM_CONFIG:
        {
            LOGI("receive MGMT_OP_READ_DEF_SYSTEM_CONFIG status(%d)", status);
            sem_post(&bluez_adapter_sem);
            break;
        }

        case MGMT_OP_SET_POWERED:
        {
            LOGI("receive MGMT_OP_SET_POWERED status(%d)", status);
            break;
        }
            
        case MGMT_OP_DISCONNECT:
        {
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            const struct mgmt_rp_disconnect *rp = param;

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, rp->addr.bdaddr.b, 6);
            bdaddr.addr_type = rp->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);
            uint8_t reason = MGMT_DEV_DISCONN_LOCAL_HOST;
            evt_param.disconnect.reason = reason;
            conn_info_del_gatts(evt_param.conn_handle, bdaddr);
            uhos_ble_gap_callback(UHOS_BLE_GAP_EVT_DISCONNET, &evt_param);
            break;
        }
        default:
            break;
    }
}

static void stack_gatt_server_callback(uhos_ble_gatts_evt_t evt, uhos_ble_gatts_evt_param_t *param, uint8_t addr[6], uint8_t addr_type)
{
    struct addr_info bdaddr;
    bdaddr.addr_type = addr_type;
    memcpy(bdaddr.addr, addr, 6);

    param->conn_handle = conn_info_get_handle_by_addr(bdaddr);
    LOGD("%s conn_handle = %04x", __FUNCTION__, param->conn_handle);

    uhos_ble_gatts_callback(evt, param);
}

uhos_ble_status_t uhos_ble_enable(void)
{
    int ret = 0;
    uint16_t hci_index = MGMT_INDEX_NONE;

    if (bluez_daemon_tid != (pthread_t)0) {
        LOGI("bluez daemon is already init");
        return UHOS_BLE_ERROR;
    }

    conn_info_init();
    sem_init(&bluez_adapter_sem, 0, 0);
    bluez_gap_register_callback(stack_gap_cmd_callback, stack_gap_event_callback);
    bluez_gatts_register_callback(stack_gatt_server_callback);
    ret = pthread_create(&bluez_daemon_tid, NULL, bluez_daemon, &hci_index);
    if (ret != 0) {
        LOGI("Error creating thread!");
        sem_destroy(&bluez_adapter_sem);
        return UHOS_BLE_ERROR;
    }

    sem_wait(&bluez_adapter_sem);
    bluez_gatts_server_start();
    LOGI("create bluez_daemon success!");
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_disable(void)
{
    if (bluez_daemon_tid == (pthread_t)0) {
        LOGI("bluez daemon isn't inited yet!");
        return UHOS_BLE_ERROR;
    }
    
    pthread_kill(bluez_daemon_tid, SIGTERM);
    pthread_join(bluez_daemon_tid, NULL);
    bluez_daemon_tid = (pthread_t)0;
    conn_info_deinit();
    LOGI("bluez daemon exit successfully");

    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_address_get(uhos_ble_addr_t mac)
{   
    bluez_gap_get_address((uint8_t * )mac);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_start(uhos_u16 conn_handle)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_get_detect(uhos_u16 conn_handle, uhos_s8 *rssi)
{
    struct addr_info bdaddr;
    conn_info_get_addr_by_handle(conn_handle, &bdaddr);
    bluez_gap_get_conn_rssi(bdaddr.addr, bdaddr.addr_type, rssi);
    return UHOS_BLE_SUCCESS;
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_get(uhos_u16 conn_handle, uhos_s8 *rssi)
{
    struct addr_info bdaddr;
    conn_info_get_addr_by_handle(conn_handle, &bdaddr);
    bluez_gap_get_conn_rssi(bdaddr.addr, bdaddr.addr_type, rssi);
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

uhos_ble_status_t uhos_ble_gap_adv_data_set(
    uhos_u8 const *p_data, 
    uhos_u8 dlen,
    uhos_u8 const *p_sr_data,
    uhos_u8 srdlen)
{
    bluez_gap_set_adv_data(p_data, dlen, p_sr_data, srdlen);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_adv_start(uhos_ble_gap_adv_param_t *p_adv_param)
{  
    bluez_gap_set_adv_start(p_adv_param->adv_type, p_adv_param->adv_interval_max, p_adv_param->adv_interval_min);
    LOGI("adv start\r\n\n");
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_reset_adv_start(void)
{
    bluez_gap_set_adv_restart();
    LOGI("adv reset\r\n\n");
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_adv_stop(void)
{
    bluez_gap_set_adv_stop();
    LOGI("adv stop\r\n\n");
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_scan_start(
    uhos_ble_gap_scan_type_t scan_type,
    uhos_ble_gap_scan_param_t scan_param)
{
    bluez_gap_set_scan_start(scan_type, scan_param.scan_interval,
                             scan_param.scan_window, scan_param.timeout);
    LOGI("scan start\r\n\n");
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_scan_stop(void)
{
    bluez_gap_set_scan_stop();
    LOGI("scan stop\r\n\n");
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_update_conn_params(
    uhos_u16 conn_handle,
    uhos_ble_gap_conn_param_t conn_params)
{
    // mgmt 
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_disconnect(uhos_u16 conn_handle)
{
    // mgmt disconncet;
    bdaddr_t bdaddr;
    uint8_t bdaddr_type;
    struct addr_info info;

    conn_info_get_addr_by_handle(conn_handle, &info);
    LOGW("disconnect conn_handle(%04x)", conn_handle);
    memcpy(bdaddr.b, info.addr, 6);

    bluez_gap_disconnect(&bdaddr, info.addr_type);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_connect(uhos_ble_gap_scan_param_t scan_param,
                                              uhos_ble_gap_connect_t conn_param)
{
    // gatt client
    
    return UHOS_BLE_SUCCESS;
}

/**************************************************************************************************/
/* BLE GATT层server相关功能接口原型                                                                 */
/**************************************************************************************************/

#define APP_MAX_SERVICE_NUM                     10
#define UHOS_BLE_GATTS_MAX_USERS                4

uhos_ble_gatts_cb_t     g_uhos_ble_pal_gatts_cb_table[UHOS_BLE_GATTS_MAX_USERS] = { NULL };
uhos_u8                 g_gatts_users = 0;

static uhos_ble_status_t uhos_ble_gatts_callback(uhos_ble_gatts_evt_t evt, uhos_ble_gatts_evt_param_t *param)
{
    int i = 0;
    uhos_ble_gatts_cb_t cb = UHOS_NULL;
    while (i < g_gatts_users) {
        if (g_uhos_ble_pal_gatts_cb_table[i] != UHOS_NULL) {
            cb = g_uhos_ble_pal_gatts_cb_table[i];
            cb(evt, param);
        }
        i++;
    }
}

uhos_ble_status_t uhos_ble_gatts_callback_register(uhos_ble_gatts_cb_t cb)
{
    int i = 0;
    while (i < UHOS_BLE_GATTS_MAX_USERS) {
        if (g_uhos_ble_pal_gatts_cb_table[i] == UHOS_NULL) {
            g_uhos_ble_pal_gatts_cb_table[i] = cb;
            g_gatts_users ++;
            return UHOS_BLE_SUCCESS;
        }
        i++;
   }
   return UHOS_BLE_ERROR;  // full
}

static uhos_ble_status_t uhos_ble_gatts_add_service(uhos_ble_gatts_srv_db_t *p_srv_db)
{
    bluez_gatts_add_service(p_srv_db);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_service_set(uhos_ble_gatts_db_t *uhos_ble_service_database)
{
    uhos_ble_gatts_srv_db_t     *p_srv_db;
    uhos_u8                     srv_num = 0;
    uhos_ble_status_t           status;

    srv_num = uhos_ble_service_database->srv_num;

    if (srv_num > APP_MAX_SERVICE_NUM || srv_num == 0) {
        LOGE("srv num limited");
        return UHOS_BLE_ERROR;
    }

    bluez_gatts_server_start();

    for (int i = 0; i < srv_num; i ++) {
        p_srv_db = &uhos_ble_service_database->p_srv_db[i];
        status = uhos_ble_gatts_add_service(p_srv_db);
        if (UHOS_BLE_SUCCESS != status) {
            LOGW("ble add service failed, %d", i);
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
    if (offset == 0) {
        if (true == bluez_gatts_send_notification(char_value_handle, p_value, len)) {
            return UHOS_BLE_SUCCESS;
        } else {
            return UHOS_BLE_ERROR;
        }
    } else {
        if (true == bluez_gatts_send_indication(char_value_handle, p_value, len)) {
            return UHOS_BLE_SUCCESS;
        } else {
            return UHOS_BLE_ERROR;
        }
    }
}

uhos_ble_status_t uhos_ble_gatts_mtu_default_set(uhos_u16 mtu)
{
    // bt_gatt_exchange_mtu(context->att, mtu, NULL, NULL, NULL);
    bluez_gatts_set_mtu(mtu);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_mtu_get(uhos_u16 conn_handle, uhos_u16 *mtu_size)
{
    bluez_gatts_get_mtu(mtu_size);
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

uhos_ble_status_t uhos_ble_gap_white_list_add(uhos_u8 *mac)
{

    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_white_list_remove(uhos_u8 *mac)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_white_list_clear(void)
{

    return UHOS_BLE_SUCCESS;
}

/**
 * @brief       取消连接
 * @return      uhos_ble_status_t
 */
uhos_ble_status_t uhos_ble_gap_cancel_connection(void)
{
    return UHOS_BLE_SUCCESS;
}


uhos_ble_status_t uhos_ble_gattc_write_without_rsp(uhos_u16 conn_handle, uhos_u16 char_value_handle, uhos_u8 *p_value, uhos_u16 len)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_exchange_mtu(uhos_u16 conn_handle, uhos_u16 mtu)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_mtu_get(uhos_u16 conn_handle, uhos_u16 *mtu_size)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_primary_service_discover_all(uhos_u16 conn_handle, void *req)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_char_discover_of_service(uhos_u16 conn_handle, uhos_ble_handle_range_t *char_handle_range)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gattc_read_char_value(uhos_u16 conn_handle, uhos_u16 char_value_handle)
{
    return UHOS_BLE_SUCCESS;
}
