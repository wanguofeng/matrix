/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */
#ifndef __CONN_INFO_H__
#define __CONN_INFO_H__

#include <stdint.h>

struct addr_info {
    uint8_t     addr[6];
	uint8_t		addr_type;
};

struct conn_info {
    uint16_t    		conn_handle;
	struct addr_info	bdaddr;
};

void conn_info_init();
void conn_info_deinit();
void conn_info_add_gatts(uint16_t conn_handle, const struct addr_info bdaddr);
void conn_info_del_gatts(uint16_t conn_handle, const struct addr_info bdaddr);
void conn_info_add_gattc(uint16_t conn_handle, const struct addr_info bdaddr);
void conn_info_del_gattc(uint16_t conn_handle, const struct addr_info bdaddr);

uint8_t conn_info_get_role_by_addr(const struct addr_info bdaddr);
uint8_t conn_info_get_role_by_handle(uint16_t conn_handle);
uint8_t conn_info_get_addr_by_handle(uint16_t conn_handle, struct addr_info * bdaddr);
uint16_t conn_info_get_handle_by_addr(const struct addr_info bdaddr);
uint16_t conn_info_generate_handle();

#endif
