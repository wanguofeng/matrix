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
#include "src/shared/util.h"
#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "peripheral/gap.h"
#include "peripheral/uh_ble.h"

/*
 * BLE COMMON
*/
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

static pthread_t bluez_daemon_tid = (pthread_t)0;

static void * bluez_daemon(void *arg) {
	
	int exit_status;

    sem_t * bluez_sem = (sem_t *)arg;
	
	mainloop_init();

	printf("Bluetooth periperhal ver %s\n", VERSION);
	
    // bluez_gap_set_mgmt_index(1);

	bluez_gap_init();

    sem_post(bluez_sem);
	
    exit_status = mainloop_run_with_signal(signal_callback, NULL);
	
    printf("bluez daemon exit_status(%d)\n", exit_status);

	bluez_gap_uinit();
	
    pthread_exit(NULL);
}

static void stack_gap_event_callback(uint16_t event, uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
    switch(event)
    {
        case 0x01:
            break;
        case 0x02:
            break;
        default:
            break;
    }
}

static void stack_gap_cmd_callback(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data)
{
    switch(cmd)
    {
        case 0x01:
            break;
        case 0x02:
            break;
        default:
            break;
    }
}

uhos_ble_status_t uhos_ble_enable(void)
{
    int ret = 0;

    if (bluez_daemon_tid != (pthread_t)0) {
        printf("bluez daemon is already init\n");
        return UHOS_BLE_ERROR;
    }
    
    sem_t bluez_sem;
	sem_init(&bluez_sem, 0, 0);
    
    ret = pthread_create(&bluez_daemon_tid, NULL, bluez_daemon, &bluez_sem);
    if (ret != 0) {
        sem_destroy(&bluez_sem);
        printf("Error creating thread!\n");
        return UHOS_BLE_ERROR;
    }

    sem_wait(&bluez_sem);

    bluez_gap_register_callback(stack_gap_cmd_callback, stack_gap_event_callback);

    bluez_gap_adapter_init(1);

    sem_destroy(&bluez_sem);

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
    bluez_gap_get_address((uint8_t * )mac);
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

uhos_ble_status_t uhos_ble_gap_adv_data_set(
    uhos_u8 const *p_data, 
    uhos_u8 dlen,
    uhos_u8 const *p_sr_data,
    uhos_u8 srdlen)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_adv_start(uhos_ble_gap_adv_param_t *p_adv_param)
{
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_reset_adv_start(void)
{
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_adv_stop(void)
{
    return UHOS_BLE_SUCCESS; 
}

uhos_ble_status_t uhos_ble_gap_scan_start(
    uhos_ble_gap_scan_type_t scan_type,
    uhos_ble_gap_scan_param_t scan_param)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_scan_stop(void)
{
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
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gap_connect(uhos_ble_gap_scan_param_t scan_param,
                                              uhos_ble_gap_connect_t conn_param)
{
    return UHOS_BLE_SUCCESS;
}

/**************************************************************************************************/
/* BLE GATT层server相关功能接口原型                                                               */
/**************************************************************************************************/
uhos_ble_status_t uhos_ble_gatts_callback_register(uhos_ble_gatts_cb_t cb)
{
    return UHOS_BLE_SUCCESS;
}

uhos_ble_status_t uhos_ble_gatts_service_set(uhos_ble_gatts_db_t *uhos_ble_service_database)
{
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
