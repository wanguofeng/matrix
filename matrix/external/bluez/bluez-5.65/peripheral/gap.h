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

void bluez_gap_init(void);
void bluez_gap_uinit(void);
void bluez_gap_adapter_init(uint16_t index);
void bluez_gap_get_address(uint8_t *mac);
void bluez_gap_set_static_address(uint8_t addr[6]);
void bluez_gap_set_adv_data(uint8_t * adv_data, uint8_t adv_data_len, uint8_t * scan_rsp, uint8_t scan_rsp_len);
void bluez_gap_adv_start();
void bluez_gap_adv_stop();
