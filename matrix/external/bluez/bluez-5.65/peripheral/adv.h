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

typedef void (*bluez_gap_event_callback_func)(uint16_t event, const void *data, uint8_t size, void *user_data);
extern void bluez_register_gap_event_callback(bluez_gap_event_callback_func func);
extern void * bluez_daemon(void *args);
extern void bluez_get_bd_addr(uint8_t * addr);
extern void bluez_set_scan_param(uint8_t scan_type, uint16_t interval, uint16_t window);
extern void bluez_set_scan_enable(uint8_t enable);
extern void bluez_set_adv_data(uint8_t const *p_data, uint8_t dlen,
						        uint8_t const *p_sr_data, uint8_t srdlen);
extern void bluez_set_adv_param(uint16_t min_interval, uint16_t max_interval, 
						        uint8_t adv_type, uint8_t direct_addr_type,
                                uint8_t channel_map);
extern void bluez_set_adv_start(uint8_t enable);
extern void bluez_set_gap_connect(uint16_t scan_interval, uint16_t scan_window,
					uint8_t peer_addr_type, uint8_t peer_addr[6], uint8_t own_addr_type,
					uint16_t min_interval, uint16_t max_interval, uint16_t latency, uint16_t supv_timeout);
extern void bluez_set_gap_disconnect(uint16_t conn_handle);


					