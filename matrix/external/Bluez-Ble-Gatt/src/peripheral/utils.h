/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
 *
 *
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>

const char *opcode_str(uint32_t opcode);
const char *get_adv_pdu_type(uint16_t adv_type);
uint8_t le16(uint8_t data);
size_t bin2hex(const uint8_t *buf, size_t buflen, char *str, size_t strlen);
char *system_config_type_str(uint16_t type);
void print_mgmt_tlv(void *data, void *user_data);
char *eir_get_name(const uint8_t *eir, uint16_t eir_len);
unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len);
const char *typestr(uint8_t type);
#endif
