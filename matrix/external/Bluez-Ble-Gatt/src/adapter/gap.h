/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdint.h>
#include "adapter/uh_ble.h"

#define	ADV_IND							0x00
#define	ADV_DIRECT_IND					0x01
#define	ADV_SCAN_IND 					0x02
#define	ADV_NONCONN_IND					0x03

typedef uhos_ble_status_t (*bluez_gap_callback_func)(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param);
typedef void (*bluez_init_callback_func)(uhos_u8 status);

int bluez_gap_init(bluez_init_callback_func func);
void bluez_gap_uinit(void);
void bluez_gap_get_address(uint8_t *mac);
void bluez_gap_register_callback(bluez_gap_callback_func func);
void bluez_gap_set_static_address(uint8_t addr[6]);
void bluez_gap_set_adv_data(uint8_t const * adv, uint8_t adv_len, uint8_t const * scan_rsp, uint8_t scan_rsp_len);
void bluez_gap_set_adv_start(uint8_t adv_type, uint16_t max_interval, uint16_t min_interval);
void bluez_gap_set_adv_stop();
void bluez_gap_set_adv_restart();
void bluez_gap_set_scan_start(uint8_t scan_type, uint16_t scan_interval, uint16_t scan_window, uint16_t timeout);
void bluez_gap_set_scan_stop();
void bluez_gap_get_conn_rssi(uint16_t conn_handle, uint8_t *rssi);
void bluez_gap_get_mtu(uint16_t *mtu);
void bluez_gap_disconnect(uint16_t conn_handle);
