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

#include <stdio.h>
#include <string.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"

#include "monitor/bt.h"
#include "src/shared/hci.h"
#include "src/shared/crypto.h"

#include "peripheral/gatt.h"
#include "peripheral/gap.h"

#include <semaphore.h>

static struct mgmt *mgmt = NULL;
static uint16_t mgmt_index = MGMT_INDEX_NONE;
static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;

static bool adv_features = false;
static bool adv_instances = false;
static bool require_connectable = true;

static uint8_t static_addr[6] = { 0x00 };
static uint8_t dev_name[260] = { 0x00, };
static uint8_t dev_name_len = 0;

static struct bt_hci *hci_dev;

#define L_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct mgmt_cmd {
	uint16_t opcode;
	const char *desc;
};

static struct mgmt_cmd cmds[] = {
	{ MGMT_OP_READ_VERSION, "MGMT_OP_READ_VERSION" },
	{ MGMT_OP_READ_COMMANDS, "MGMT_OP_READ_COMMANDS" },
	{ MGMT_OP_READ_INDEX_LIST, "MGMT_OP_READ_INDEX_LIST" },
	{ MGMT_OP_READ_INFO, "MGMT_OP_READ_INFO"} ,
	{ MGMT_OP_SET_POWERED, "MGMT_OP_SET_POWERED" },
	{ MGMT_OP_SET_DISCOVERABLE, "MGMT_OP_SET_DISCOVERABLE" },
	{ MGMT_OP_SET_CONNECTABLE, "MGMT_OP_SET_CONNECTABLE" },
	{ MGMT_OP_SET_FAST_CONNECTABLE, "MGMT_OP_SET_FAST_CONNECTABLE" },
	{ MGMT_OP_SET_BONDABLE, "MGMT_OP_SET_BONDABLE" },
	{ MGMT_OP_SET_LINK_SECURITY, "MGMT_OP_SET_LINK_SECURITY" },
	{ MGMT_OP_SET_SSP, "MGMT_OP_SET_SSP" },
	{ MGMT_OP_SET_HS, "MGMT_OP_SET_HS" },
	{ MGMT_OP_SET_LE, "MGMT_OP_SET_LE" },
	{ MGMT_OP_SET_DEV_CLASS, "MGMT_OP_SET_DEV_CLASS" },
	{ MGMT_OP_SET_LOCAL_NAME, "MGMT_OP_SET_LOCAL_NAME" },
	{ MGMT_OP_ADD_UUID, "MGMT_OP_ADD_UUID" },
	{ MGMT_OP_REMOVE_UUID, "MGMT_OP_REMOVE_UUID" },
	{ MGMT_OP_LOAD_LINK_KEYS, "MGMT_OP_LOAD_LINK_KEYS" },
	{ MGMT_OP_LOAD_LONG_TERM_KEYS, "MGMT_OP_LOAD_LONG_TERM_KEYS" },
	{ MGMT_OP_DISCONNECT, "MGMT_OP_DISCONNECT" },
	{ MGMT_OP_GET_CONNECTIONS, "MGMT_OP_GET_CONNECTIONS" },
	{ MGMT_OP_PIN_CODE_REPLY, "MGMT_OP_PIN_CODE_REPLY" },
	{ MGMT_OP_PIN_CODE_NEG_REPLY, "MGMT_OP_PIN_CODE_NEG_REPLY" },
	{ MGMT_OP_SET_IO_CAPABILITY, "MGMT_OP_SET_IO_CAPABILITY" },
	{ MGMT_OP_PAIR_DEVICE, "MGMT_OP_PAIR_DEVICE" },
	{ MGMT_OP_CANCEL_PAIR_DEVICE, "MGMT_OP_CANCEL_PAIR_DEVICE" },
	{ MGMT_OP_UNPAIR_DEVICE, "MGMT_OP_UNPAIR_DEVICE" },
	{ MGMT_OP_USER_CONFIRM_REPLY, "MGMT_OP_USER_CONFIRM_REPLY" },
	{ MGMT_OP_USER_CONFIRM_NEG_REPLY, "MGMT_OP_USER_CONFIRM_NEG_REPLY" },
	{ MGMT_OP_USER_PASSKEY_REPLY, "MGMT_OP_USER_PASSKEY_REPLY" },
	{ MGMT_OP_USER_PASSKEY_NEG_REPLY, "MGMT_OP_USER_PASSKEY_NEG_REPLY" },
	{ MGMT_OP_READ_LOCAL_OOB_DATA, "MGMT_OP_READ_LOCAL_OOB_DATA" },
	{ MGMT_OP_ADD_REMOTE_OOB_DATA, "MGMT_OP_ADD_REMOTE_OOB_DATA" },
	{ MGMT_OP_REMOVE_REMOTE_OOB_DATA, "MGMT_OP_REMOVE_REMOTE_OOB_DATA" },
	{ MGMT_OP_START_DISCOVERY, "MGMT_OP_START_DISCOVERY" },
	{ MGMT_OP_STOP_DISCOVERY, "MGMT_OP_STOP_DISCOVERY" },
	{ MGMT_OP_CONFIRM_NAME, "MGMT_OP_CONFIRM_NAME" },
	{ MGMT_OP_BLOCK_DEVICE, "MGMT_OP_BLOCK_DEVICE" },
	{ MGMT_OP_UNBLOCK_DEVICE, "MGMT_OP_UNBLOCK_DEVICE" },
	{ MGMT_OP_SET_DEVICE_ID, "MGMT_OP_SET_DEVICE_ID" },
	{ MGMT_OP_SET_ADVERTISING, "MGMT_OP_SET_ADVERTISING" },
	{ MGMT_OP_SET_BREDR, "MGMT_OP_SET_BREDR" },
	{ MGMT_OP_SET_STATIC_ADDRESS, "MGMT_OP_SET_STATIC_ADDRESS" },
	{ MGMT_OP_SET_SCAN_PARAMS, "MGMT_OP_SET_SCAN_PARAMS" },
	{ MGMT_OP_SET_SECURE_CONN, "MGMT_OP_SET_SECURE_CONN" },
	{ MGMT_OP_SET_DEBUG_KEYS, "MGMT_OP_SET_DEBUG_KEYS" },
	{ MGMT_OP_SET_PRIVACY, "MGMT_OP_SET_PRIVACY" },
	{ MGMT_OP_LOAD_IRKS, "MGMT_OP_LOAD_IRKS" },
	{ MGMT_OP_GET_CONN_INFO, "MGMT_OP_GET_CONN_INFO" },
	{ MGMT_OP_GET_CLOCK_INFO, "MGMT_OP_GET_CLOCK_INFO" },
	{ MGMT_OP_ADD_DEVICE, "MGMT_OP_ADD_DEVICE" },
	{ MGMT_OP_REMOVE_DEVICE, "MGMT_OP_REMOVE_DEVICE" },
	{ MGMT_OP_LOAD_CONN_PARAM, "MGMT_OP_LOAD_CONN_PARAM" },
	{ MGMT_OP_READ_UNCONF_INDEX_LIST, "MGMT_OP_READ_UNCONF_INDEX_LIST" },
	{ MGMT_OP_READ_CONFIG_INFO, "MGMT_OP_READ_CONFIG_INFO" },
	{ MGMT_OP_SET_EXTERNAL_CONFIG, "MGMT_OP_SET_EXTERNAL_CONFIG" },
	{ MGMT_OP_SET_PUBLIC_ADDRESS, "MGMT_OP_SET_PUBLIC_ADDRESS" },
	{ MGMT_OP_START_SERVICE_DISCOVERY, "MGMT_OP_START_SERVICE_DISCOVERY" },
	{ MGMT_OP_READ_LOCAL_OOB_EXT_DATA, "MGMT_OP_READ_LOCAL_OOB_EXT_DATA" },
	{ MGMT_OP_READ_EXT_INDEX_LIST, "MGMT_OP_READ_EXT_INDEX_LIST" },
	{ MGMT_OP_READ_ADV_FEATURES, "MGMT_OP_READ_ADV_FEATURES" },
	{ MGMT_OP_ADD_ADVERTISING, "MGMT_OP_ADD_ADVERTISING" },
	{ MGMT_OP_REMOVE_ADVERTISING, "MGMT_OP_REMOVE_ADVERTISING" },
	{ MGMT_OP_GET_ADV_SIZE_INFO, "MGMT_OP_GET_ADV_SIZE_INFO" }, 
	{ MGMT_OP_START_LIMITED_DISCOVERY, "MGMT_OP_START_LIMITED_DISCOVERY" },
	{ MGMT_OP_READ_EXT_INFO, "MGMT_OP_READ_EXT_INFO" },
	{ MGMT_OP_SET_APPEARANCE, "MGMT_OP_SET_APPEARANCE" },
	{ MGMT_OP_GET_PHY_CONFIGURATION, "MGMT_OP_GET_PHY_CONFIGURATION" },
	{ MGMT_OP_SET_PHY_CONFIGURATION, "MGMT_OP_SET_PHY_CONFIGURATION" },
	{ MGMT_OP_SET_BLOCKED_KEYS, "MGMT_OP_SET_BLOCKED_KEYS" },
	{ MGMT_OP_SET_WIDEBAND_SPEECH, "MGMT_OP_SET_WIDEBAND_SPEECH" },
	{ MGMT_OP_READ_CONTROLLER_CAP, "MGMT_OP_READ_CONTROLLER_CAP" },
	{ MGMT_OP_READ_EXP_FEATURES_INFO, "MGMT_OP_READ_EXP_FEATURES_INFO" },
	{ MGMT_OP_SET_EXP_FEATURE, "MGMT_OP_SET_EXP_FEATURE" },
	{ MGMT_OP_READ_DEF_SYSTEM_CONFIG, "MGMT_OP_READ_DEF_SYSTEM_CONFIG" },
	{ MGMT_OP_SET_DEF_SYSTEM_CONFIG, "MGMT_OP_SET_DEF_SYSTEM_CONFIG" },
	{ MGMT_OP_READ_DEF_RUNTIME_CONFIG, "MGMT_OP_READ_DEF_RUNTIME_CONFIG" },
	{ MGMT_OP_SET_DEF_RUNTIME_CONFIG, "MGMT_OP_SET_DEF_RUNTIME_CONFIG" },
	{ MGMT_OP_GET_DEVICE_FLAGS, "MGMT_OP_GET_DEVICE_FLAGS" },
	{ MGMT_OP_SET_DEVICE_FLAGS, "MGMT_OP_SET_DEVICE_FLAGS" },
	{ MGMT_OP_READ_ADV_MONITOR_FEATURES, "MGMT_OP_READ_ADV_MONITOR_FEATURES" },
	{ MGMT_OP_ADD_ADV_PATTERNS_MONITOR, "MGMT_OP_ADD_ADV_PATTERNS_MONITOR" },
	{ MGMT_OP_REMOVE_ADV_MONITOR, "MGMT_OP_REMOVE_ADV_MONITOR" },
	{ MGMT_OP_ADD_EXT_ADV_PARAMS, "MGMT_OP_ADD_EXT_ADV_PARAMS" },
	{ MGMT_OP_ADD_EXT_ADV_DATA, "MGMT_OP_ADD_EXT_ADV_DATA" },
	{ MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI, "MGMT_OP_ADD_ADV_PATTERNS_MONITOR_RSSI" },
};

static const struct mgmt_cmd *get_cmd(uint16_t opcode)
{
	uint32_t n;

	for (n = 0; n < L_ARRAY_SIZE(cmds); n++) {
		if (opcode == cmds[n].opcode)
			return &cmds[n];
	}

	return NULL;
}

static const char *opcode_str(uint32_t opcode)
{
	const struct mgmt_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return "Unknown";

	return cmd->desc;
}

static void cmd_callback(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data)
{

}

static void event_callback(uint16_t event, uint16_t index, uint16_t length,
							const void *param, void *user_data)
{

}

static void add_advertising(uint16_t index)
{
	const char ad[] = { 0x11, 0x15,
			0xd0, 0x00, 0x2d, 0x12, 0x1e, 0x4b, 0x0f, 0xa4,
			0x99, 0x4e, 0xce, 0xb5, 0x31, 0xf4, 0x05, 0x79 };
	struct mgmt_cp_add_advertising *cp;
	void *buf;

	buf = malloc(sizeof(*cp) + sizeof(ad));
	if (!buf)
		return;

	memset(buf, 0, sizeof(*cp) + sizeof(ad));
	cp = buf;
	cp->instance = 0x01;
	cp->flags = cpu_to_le32((1 << 0) | (1 << 1) | (1 << 4));
	cp->duration = cpu_to_le16(0);
	cp->timeout = cpu_to_le16(0);
	cp->adv_data_len = sizeof(ad);
	cp->scan_rsp_len = 0;
	memcpy(cp->data, ad, sizeof(ad));

	mgmt_send(mgmt, MGMT_OP_ADD_ADVERTISING, index,
			sizeof(*cp) + sizeof(ad), buf, NULL, NULL, NULL);

	free(buf);
}

static void enable_advertising(uint16_t index)
{
	uint8_t val;

	val = require_connectable ? 0x01 : 0x00;
	mgmt_send(mgmt, MGMT_OP_SET_CONNECTABLE, index, 1, &val,
						NULL, NULL, NULL);

	// val = 0x01;
	// mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
	// 					NULL, NULL, NULL);

	printf("adv_instances = %d\n", adv_instances);
	
	if (adv_instances) {

		add_advertising(index);
		return;
	}

	val = require_connectable ? 0x01 : 0x02;
	mgmt_send(mgmt, MGMT_OP_SET_ADVERTISING, index, 1, &val,
						NULL, NULL, NULL);
}

void bluez_gap_adv_stop()
{
	uint8_t val = 0x00;
	mgmt_send(mgmt, MGMT_OP_SET_ADVERTISING, mgmt_index, 1, &val,
						NULL, NULL, NULL);
}

void bluez_gap_adv_start()
{
	// enable_advertising(mgmt_index);
}

static void new_settings_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("New settings\n");
}

static void local_name_changed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Local name changed\n");
}

static void new_long_term_key_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("New long term key\n");
}

static void device_connected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Device connected\n");
}

static void device_disconnected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Device disconnected\n");
}

static void user_confirm_request_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("User confirm request\n");
}

static void user_passkey_request_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("User passkey request\n");
}

static void auth_failed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Authentication failed\n");
}

static void device_unpaired_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Device unpaired\n");
}

static void passkey_notify_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Passkey notification\n");
}

static void new_irk_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("New identify resolving key\n");
}

static void new_csrk_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("New connection signature resolving key\n");
}

static void new_conn_param_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("New connection parameter\n");
}

static void advertising_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Advertising added\n");
}

static void advertising_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Advertising removed\n");
}

static void read_adv_features_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_adv_features *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	uint32_t flags;

	flags = le32_to_cpu(rp->supported_flags);

	cmd_callback(MGMT_OP_READ_ADV_FEATURES, status, len, param, user_data);

	printf("max_instances = %d, num_instances = %d, flags = %08x\n", rp->max_instances, rp->num_instances, flags);

	if (rp->max_instances > 0) {
		adv_instances = true;
		if (flags & MGMT_ADV_FLAG_CONNECTABLE)
			require_connectable = true;
	} else
		require_connectable = false;
	// enable_advertising(index);
}

static void read_info_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	uint32_t required_settings = MGMT_SETTING_LE |
					MGMT_SETTING_STATIC_ADDRESS;
	uint32_t supported_settings, current_settings;
	uint8_t val;

	required_settings = MGMT_SETTING_LE;

	cmd_callback(MGMT_OP_READ_INFO, status, len, param, user_data);

	if (status) {
		fprintf(stderr, "Reading info for index %u failed: %s\n",
						index, mgmt_errstr(status));
		return;
	}

	supported_settings = le32_to_cpu(rp->supported_settings);
	current_settings = le32_to_cpu(rp->current_settings);

	if ((supported_settings & required_settings) != required_settings) {
		printf("index %d doesn't support BLE Features \n", index);
		return;
	}

	if ((mgmt_index != MGMT_INDEX_NONE) && (mgmt_index != index)) {
		printf("Selecting index %u already\n", mgmt_index);
		return;
	}

	printf("Selecting index %u\n", index);

	mgmt_index = index;

	memcpy(static_addr, (uint8_t *)&rp->bdaddr, 6);

	hci_dev = bt_hci_new_user_channel(mgmt_index);
	if (!hci_dev) {
		fprintf(stderr, "Failed to open HCI for advertiser\n");
		return;
	}

	// mgmt_register(mgmt, MGMT_EV_NEW_SETTINGS, index,
	// 				new_settings_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_LOCAL_NAME_CHANGED, index,
	// 				local_name_changed_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_NEW_LONG_TERM_KEY, index,
	// 				new_long_term_key_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_DEVICE_CONNECTED, index,
	// 				device_connected_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_DEVICE_DISCONNECTED, index,
	// 				device_disconnected_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_USER_CONFIRM_REQUEST, index,
	// 				user_confirm_request_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_USER_PASSKEY_REQUEST, index,
	// 				user_passkey_request_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_AUTH_FAILED, index,
	// 				auth_failed_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_DEVICE_UNPAIRED, index,
	// 				device_unpaired_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_PASSKEY_NOTIFY, index,
	// 				passkey_notify_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_NEW_IRK, index,
	// 				new_irk_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_NEW_CSRK, index,
	// 				new_csrk_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_NEW_CONN_PARAM, index,
	// 				new_conn_param_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_ADVERTISING_ADDED, index,
	// 				advertising_added_event, NULL, NULL);
	// mgmt_register(mgmt, MGMT_EV_ADVERTISING_REMOVED, index,
	// 				advertising_removed_event, NULL, NULL);

	// dev_name_len = snprintf((char *) dev_name, 26, "uhos gatt-server demo");

	// if (current_settings & MGMT_SETTING_POWERED) {
	// 	val = 0x00;
	// 	mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// if (!(current_settings & MGMT_SETTING_LE)) {
	// 	val = 0x01;
	// 	mgmt_send(mgmt, MGMT_OP_SET_LE, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// if (!(current_settings & MGMT_SETTING_CONNECTABLE)) {
	// 	val = 0x01;
	// 	mgmt_send(mgmt, MGMT_OP_SET_CONNECTABLE, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// if (current_settings & MGMT_SETTING_BREDR) {
	// 	val = 0x00;
	// 	mgmt_send(mgmt, MGMT_OP_SET_BREDR, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// if ((supported_settings & MGMT_SETTING_SECURE_CONN) &&
	// 		!(current_settings & MGMT_SETTING_SECURE_CONN)) {
	// 	val = 0x01;
	// 	mgmt_send(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// if (current_settings & MGMT_SETTING_DEBUG_KEYS) {
	// 	val = 0x00;
	// 	mgmt_send(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	/* disable bond support. */
	// if ((current_settings & MGMT_SETTING_BONDABLE)) {
	// 	val = 0x00;
	// 	mgmt_send(mgmt, MGMT_OP_SET_BONDABLE, index, 1, &val,
	// 						NULL, NULL, NULL);
	// }

	// // mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index,
	// // 				6, static_addr, NULL, NULL, NULL);

	// mgmt_send(mgmt, MGMT_OP_SET_LOCAL_NAME, index,
	// 				260, dev_name, NULL, NULL, NULL);

	// if (adv_features)
	// 	mgmt_send(mgmt, MGMT_OP_READ_ADV_FEATURES, mgmt_index, 0, NULL,
	// 					read_adv_features_complete,
	// 					UINT_TO_PTR(mgmt_index), NULL);

	// val = 0x01;
	// mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
	// 						NULL, NULL, NULL);
}

void test()
{
	if (adv_features)
		mgmt_send(mgmt, MGMT_OP_READ_ADV_FEATURES, mgmt_index, 0, NULL,
						read_adv_features_complete,
						UINT_TO_PTR(mgmt_index), NULL);
	else
		enable_advertising(mgmt_index);
}

static void read_index_list_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t count;
	int i;

	cmd_callback(MGMT_OP_READ_INDEX_LIST, status, len, param, user_data);

	if (status) {
		fprintf(stderr, "Reading index list failed: %s\n",
						mgmt_errstr(status));
		return;
	}

	count = le16_to_cpu(rp->num_controllers);

	printf("Index list: %u\n", count);

	if (mgmt_index != MGMT_INDEX_NONE) {
		/* App select mgmt index*/
		mgmt_send(mgmt, MGMT_OP_READ_INFO, mgmt_index, 0, NULL,
				read_info_complete, UINT_TO_PTR(mgmt_index), NULL);
	} else {
		/* Select first support le feature controller */
		for (i = 0; i < count; i++) {
			uint16_t index = cpu_to_le16(rp->index[i]);
			mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
					read_info_complete, UINT_TO_PTR(index), NULL);
		}
	}
}

static void index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Index added\n");

	if (mgmt_index != MGMT_INDEX_NONE)
		return;

	mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
}

static void index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	printf("Index removed\n");

	if (mgmt_index != index)
		return;

	mgmt_index = MGMT_INDEX_NONE;
}

static void read_ext_index_list_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_ext_index_list *rp = param;
	uint16_t count;
	int i;

	if (status) {
		fprintf(stderr, "Reading extended index list failed: %s\n",
						mgmt_errstr(status));
		return;
	}

	count = le16_to_cpu(rp->num_controllers);

	printf("Extended index list: %u\n", count);

	for (i = 0; i < count; i++) {
		uint16_t index = cpu_to_le16(rp->entry[i].index);

		mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
	}
}

static void ext_index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_ext_index_added *ev = param;

	printf("Extended index added: %u\n", ev->type);

	if (mgmt_index != MGMT_INDEX_NONE)
		return;

	if (ev->type != 0x00)
		return;

	mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
}

static void ext_index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_ext_index_added *ev = param;

	printf("Extended index removed: %u\n", ev->type);

	if (mgmt_index != index)
		return;

	if (ev->type != 0x00)
		return;

	mgmt_index = MGMT_INDEX_NONE;
}

static void read_commands_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_commands *rp = param;
	uint16_t num_commands;
	bool ext_index_list = false;
	int i;

	cmd_callback(MGMT_OP_READ_COMMANDS, status, len, param, user_data);

	if (status) {
		fprintf(stderr, "Reading index list failed: %s\n",
						mgmt_errstr(status));
		return;
	}

	num_commands = le16_to_cpu(rp->num_commands);

	for (i = 0; i < num_commands; i++) {
		uint16_t op = get_le16(rp->opcodes + i);
		
		printf("opcode = %04x(%s)\n", op, opcode_str(op));

		if (op == MGMT_OP_READ_EXT_INDEX_LIST) {
			ext_index_list = true;
		}

		else if (op == MGMT_OP_READ_ADV_FEATURES) {
			adv_features = true;
		}
	}

	// if (ext_index_list) {
	// 	mgmt_register(mgmt, MGMT_EV_EXT_INDEX_ADDED, MGMT_INDEX_NONE,
	// 				ext_index_added_event, NULL, NULL);
	// 	mgmt_register(mgmt, MGMT_EV_EXT_INDEX_REMOVED, MGMT_INDEX_NONE,
	// 				ext_index_removed_event, NULL, NULL);

	// 	if (!mgmt_send(mgmt, MGMT_OP_READ_EXT_INDEX_LIST,
	// 			MGMT_INDEX_NONE, 0, NULL,
	// 			read_ext_index_list_complete, NULL, NULL)) {
	// 		fprintf(stderr, "Failed to read extended index list\n");
	// 		return;
	// 	}
	// } else 
	{
		mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_event, NULL, NULL);

		mgmt_register(mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_event, NULL, NULL);
                                                 
		if (!mgmt_send(mgmt, MGMT_OP_READ_INDEX_LIST,
				MGMT_INDEX_NONE, 0, NULL,
				read_index_list_complete, NULL, NULL)) {
			fprintf(stderr, "Failed to read index list\n");
			return;
		}
	}
}

static void read_version_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_version *rp = param;

	printf("Reading management Version Information: version = %d, revision = %d\n", rp->version, rp->revision);

	cmd_callback(MGMT_OP_READ_VERSION, status, len, param, user_data);

	if(status) {
		printf("Reading version failed: %s\n", mgmt_errstr(status));
	}

	if (!mgmt_send(mgmt, MGMT_OP_READ_COMMANDS,
				MGMT_INDEX_NONE, 0, NULL,
				read_commands_complete, NULL, NULL)) {
		fprintf(stderr, "Failed to read supported commands\n");
		return;
	}
}

void bluez_gap_init(void)
{
	mgmt = mgmt_new_default();
	if (!mgmt) {
		fprintf(stderr, "Failed to open management socket\n");
		return;
	}
	return ;
}

void bluez_gap_test() 
{
	sem_t semaphore;
	sem_init(&semaphore, 0, 1);
	sem_wait(&semaphore);

	if (!mgmt_send(mgmt, MGMT_OP_READ_VERSION,
				MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, &semaphore, NULL)) {
		fprintf(stderr, "Failed to read version\n");
		return;
	}

	sem_wait(&semaphore);

	if (!mgmt_send(mgmt, MGMT_OP_READ_COMMANDS,
				MGMT_INDEX_NONE, 0, NULL,
				read_commands_complete, NULL, NULL)) {
		fprintf(stderr, "Failed to read supported commands\n");
		return;
	}

	// if (user_data != NULL)
	// 	sem_post((sem_t *)user_data);

	sem_destroy(&semaphore);

	printf("%s %d\n", __FUNCTION__, __LINE__);
}

void bluez_gap_adapter_init(uint16_t hci_index)
{
	mgmt_index = hci_index;

	if (!mgmt_send(mgmt, MGMT_OP_READ_VERSION,
				MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, NULL, NULL)) {
		fprintf(stderr, "Failed to read version\n");
		return;
	}
}

void bluez_gap_get_address(uint8_t addr[6])
{
	if (mgmt_index == MGMT_INDEX_NONE)
		return;

	memcpy(addr, static_addr, sizeof(static_addr));
}

void bluez_gap_set_static_address(uint8_t addr[6])
{
	memcpy(static_addr, addr, sizeof(static_addr));

	printf("Using static address %02x:%02x:%02x:%02x:%02x:%02x\n",
			static_addr[5], static_addr[4], static_addr[3],
			static_addr[2], static_addr[1], static_addr[0]);
}

void bluez_gap_uinit(void)
{
	if (!mgmt)
		return;

	// gatt_server_stop();

    mgmt_unref(mgmt);
	mgmt = NULL;

	mgmt_index = MGMT_INDEX_NONE;
}