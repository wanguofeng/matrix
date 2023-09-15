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
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#ifndef WAIT_ANY
#define WAIT_ANY (-1)
#endif

#include "src/shared/mainloop.h"
#include "peripheral/gap.h"
#include "peripheral/gatt.h"
#include "peripheral/uh_ble.h"

#define CONFIG_LOG_TAG "bluez_adapter"
#include "peripheral/log.h"

#define bluez_adapter_version     "v1.0.23-rc-20230901"
#define UHOS_BLE_GAP_MAX_USERS                  4
#define APP_MAX_SERVICE_NUM                     10
#define UHOS_BLE_GATTS_MAX_USERS                4

static pthread_t bluez_daemon_tid = (pthread_t)0;

static uhos_ble_gap_cb_t       g_uhos_ble_pal_gap_cb_table[UHOS_BLE_GAP_MAX_USERS] = { NULL };
static uhos_u8                 g_gap_users = 0;
static uhos_ble_gatts_cb_t     g_uhos_ble_pal_gatts_cb_table[UHOS_BLE_GATTS_MAX_USERS] = { NULL };
static uhos_u8                 g_gatts_users = 0;

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

static void * bluez_daemon(void *arg)
{
    int exit_status = 0;
    sem_t * daemon_sem = (sem_t *)arg;

    LOGW("Bluetooth Adapter Version %s", bluez_adapter_version);

	mainloop_init();
	bluez_gap_init();
    bluez_gap_register_callback(uhos_ble_gap_callback);
    bluez_gatts_register_callback(uhos_ble_gatts_callback);
    sem_post(daemon_sem);

    exit_status = mainloop_run_with_signal(signal_callback, NULL);

    LOGI("bluez daemon exit_status(%d)", exit_status);

	bluez_gap_uinit();
    bluez_gatts_server_stop();
    pthread_exit(NULL);
}

/*
 * BLE COMMON
*/

uhos_ble_status_t uhos_ble_enable(void)
{
    int ret = 0;
    static sem_t daemon_sem;

    if (bluez_daemon_tid != (pthread_t)0) {
        LOGI("bluez daemon is already init");
        return UHOS_BLE_ERROR;
    }

    sem_init(&daemon_sem, 0, 0);

    ret = pthread_create(&bluez_daemon_tid, NULL, bluez_daemon, &daemon_sem);
    if (ret != 0) {
        LOGI("Error creating thread!");
        sem_destroy(&daemon_sem);
        return UHOS_BLE_ERROR;
    }

    sem_wait(&daemon_sem);
    sleep(2);
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
    bluez_gap_get_conn_rssi(conn_handle, rssi);
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_rssi_get(uhos_u16 conn_handle, uhos_s8 *rssi)
{
    bluez_gap_get_conn_rssi(conn_handle, rssi);
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
    bluez_gap_disconnect(conn_handle);
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
        bluez_gatts_send_notification(char_value_handle, p_value, len);
    } else {
        bluez_gatts_send_indication(char_value_handle, p_value, len);
    }
    return UHOS_BLE_SUCCESS;
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
