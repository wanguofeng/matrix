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

void bluez_gatt_set_static_address(uint8_t addr[6]);
void bluez_gatt_set_device_name(uint8_t name[20], uint8_t len);

void bluez_gatt_server_start(void);
void bluez_gatt_server_stop(void);
void bluez_gatt_add_service(uhos_ble_gatts_srv_db_t *p_srv_db);
