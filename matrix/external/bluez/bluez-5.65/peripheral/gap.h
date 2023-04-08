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

typedef void (*bluez_gap_event_callback_func)(uint16_t event, uint16_t index, uint16_t length,
					const void *param, void *user_data);

typedef void (*bluez_gap_cmd_callback_func)(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data);

void bluez_gap_init(void);
void bluez_gap_uinit(void);
void bluez_gap_adapter_init(uint16_t index);
void bluez_gap_get_address(uint8_t *mac);
void bluez_gap_register_callback(bluez_gap_cmd_callback_func cmd_cb, bluez_gap_event_callback_func event_cb);
void bluez_gap_set_static_address(uint8_t addr[6]);
