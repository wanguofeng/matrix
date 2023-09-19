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

#include "peripheral/uh_ble.h" 

void bluez_gatts_set_static_address(uint8_t addr[6]);
void bluez_gatts_set_device_name(uint8_t name[20], uint8_t len);

void bluez_gatts_server_start(void);
void bluez_gatts_server_stop(void);
void bluez_gatts_add_service(uhos_ble_gatts_srv_db_t *p_srv_db);

typedef void (*bluez_gatts_event_callback_func)(uhos_ble_gatts_evt_t evt, uhos_ble_gatts_evt_param_t *param,
                                                uint8_t addr[6], uint8_t addr_type);

void bluez_gatts_register_callback(bluez_gatts_event_callback_func func);
bool bluez_gatts_send_notification(uint16_t char_handle, const uint8_t *value, uint16_t length);
bool bluez_gatts_send_indication(uint16_t char_handle, const uint8_t *value, uint16_t length);
void bluez_gatts_set_mtu(uint16_t mtu);
void bluez_gatts_get_mtu(uint16_t *mtu);