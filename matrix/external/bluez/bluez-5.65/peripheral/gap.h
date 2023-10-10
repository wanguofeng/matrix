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

#define	ADV_IND							0x00
#define	ADV_DIRECT_IND					0x01
#define	ADV_SCAN_IND 					0x02
#define	ADV_NONCONN_IND					0x03

typedef void (*bluez_gap_event_callback_func)(uint16_t event, uint16_t index, uint16_t length,
					const void *param, void *user_data);

typedef void (*bluez_gap_cmd_callback_func)(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data);

void bluez_gap_init(void);
void bluez_gap_uinit(void);
void bluez_gap_revert_settings(void);
void bluez_gap_adapter_init(uint16_t index);
void bluez_gap_get_address(uint8_t *mac);
void bluez_gap_register_callback(bluez_gap_cmd_callback_func cmd_cb, bluez_gap_event_callback_func event_cb);
void bluez_gap_set_static_address(uint8_t addr[6]);
void bluez_gap_set_adv_data(uint8_t const * adv, uint8_t adv_len, uint8_t const * scan_rsp, uint8_t scan_rsp_len);
void bluez_gap_set_adv_start(uint8_t adv_type, uint16_t max_interval, uint16_t min_interval);
void bluez_gap_set_adv_stop();
void bluez_gap_set_adv_restart();
void bluez_gap_set_scan_start(uint8_t scan_type, uint16_t scan_interval, uint16_t scan_window, uint16_t timeout);
void bluez_gap_set_scan_stop();
void bluez_gap_get_conn_rssi(uint8_t *peer_addr, uint8_t type, uint8_t *rssi);
void bluez_gap_get_mtu(uint16_t *mtu);
void bluez_gap_disconnect(const bdaddr_t *bdaddr, uint8_t bdaddr_type);