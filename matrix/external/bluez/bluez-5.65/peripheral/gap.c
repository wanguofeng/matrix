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
#include <semaphore.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"
#include "peripheral/gatt.h"
#include "peripheral/gap.h"

// #include "monitor/bt.h"
// #include "emulator/vhci.h"
// #include "emulator/btdev.h"
// #include "emulator/bthost.h"
// #include "emulator/hciemu.h"

#define CONFIG_LOG_TAG "Bluez_Stack"
#include "peripheral/log.h"

static struct mgmt *mgmt = NULL;
static uint16_t mgmt_index = MGMT_INDEX_NONE;
static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;

// static struct hciemu *hciemu_stack = NULL;
// struct bthost *bthost = NULL;

static bool adv_features = false;
static bool adv_instances = false;
static bool require_connectable = true;

static uint8_t static_addr[6] = { 0x00 };
static uint8_t dev_name[260] = { 0x00, };
static uint8_t dev_name_len = 0;

#define ADV_MAX_LENGTH	31

static uint8_t g_adv_type = 0;
static uint8_t g_adv_running = false;
static uint8_t g_adv_data[ADV_MAX_LENGTH] = {0x00};
static uint8_t g_adv_data_len = 0;
static uint8_t g_scan_rsp[ADV_MAX_LENGTH] = {0x00};
static uint8_t g_scan_rsp_len = 0;

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

struct send_sync {
	sem_t sem;
	uint16_t opcode;
	uint8_t status;
	void *userdata;
};

static unsigned int mgmt_send_tlv_wrapper(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				struct mgmt_tlv_list *tlv_list,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	LOGD("mgmt_send_tlv: %s(0x%04x) index(0x%04x)", opcode_str(opcode), opcode, index);
	mgmt_send_tlv(mgmt, opcode, index, tlv_list, callback, user_data, destroy);
}

static unsigned int mgmt_send_wrapper(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				uint16_t length, const void *param,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	LOGD("mgmt_send: %s(0x%04x) index(0x%04x)", opcode_str(opcode), opcode, index);
	mgmt_send(mgmt, opcode, index, length, param, callback, user_data, destroy);
}

static void mgmt_sync_callback(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	struct send_sync * sync = (struct send_sync * )user_data;
	sync->status = status;
	LOGD("mgmt_send_sync_callback %s status(0x%02x)", opcode_str(sync->opcode), sync->status);
	sem_post(&sync->sem);
}

static unsigned int mgmt_send_sync(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				uint16_t length, const void *param, mgmt_destroy_func_t destroy)
{
	struct send_sync sync = {0x00};
	sync.opcode = opcode;
	sem_init(&sync.sem, 0, 0);

	mgmt_send(mgmt, opcode, index, length, param, mgmt_sync_callback, &sync, destroy);

	LOGD("%s:%d wait sem", __FUNCTION__, __LINE__);

	sem_wait(&sync.sem);
	sem_destroy(&sync.sem);

	LOGD("mgmt_send_sync: %s(0x%04x) status(0x%02x)", opcode_str(opcode), opcode, sync.status);
}

static bluez_gap_event_callback_func g_event_cb = NULL;
static bluez_gap_cmd_callback_func g_cmd_cb = NULL;

static void cmd_callback(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data)
{
	if (g_cmd_cb != NULL)
		g_cmd_cb(cmd, status, len, param, user_data);
}

static void event_callback(uint16_t event, uint16_t index, uint16_t length,
							const void *param, void *user_data)
{
	if (g_event_cb != NULL)
		g_event_cb(event, index, length, param, user_data);
}

/*
ADV_SCAN_IND:
	cp->flags = cpu_to_le32(0);
	scan_rsp is not empty;

ADV_IND:
	cp->flags = cpu_to_le32(MGMT_ADV_FLAG_CONNECTABLE);

ADV_NONCONN_IND:
	cp->flags = cpu_to_le32(0);
	cp->scan_rsp_len = 0;
*/

static void clear_long_term_keys(uint16_t index)
{
        struct mgmt_cp_load_long_term_keys cp;

        memset(&cp, 0, sizeof(cp));
        cp.key_count = cpu_to_le16(0);

        mgmt_send(mgmt, MGMT_OP_LOAD_LONG_TERM_KEYS, index,
                                        sizeof(cp), &cp, NULL, NULL, NULL);
}

static void clear_identity_resolving_keys(uint16_t index)
{
        struct mgmt_cp_load_irks cp;

        memset(&cp, 0, sizeof(cp));
        cp.irk_count = cpu_to_le16(0);

        mgmt_send(mgmt, MGMT_OP_LOAD_IRKS, index,
                                        sizeof(cp), &cp, NULL, NULL, NULL);
}



static void add_advertising(uint16_t index)
{
	const char ad[] = { 0x11, 0x15,
			0xd0, 0x00, 0x2d, 0x12, 0x1e, 0x4b, 0x0f, 0xa4,
			0x99, 0x4e, 0xce, 0xb5, 0x31, 0xf4, 0x05, 0x79 };

	// const char scan_rsp[] = { 0x07, 0x09, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
	struct mgmt_cp_add_advertising *cp;
	void *buf;

	// buf = malloc(sizeof(*cp) + sizeof(ad) + sizeof(scan_rsp));
	buf = malloc(sizeof(*cp) + sizeof(ad));
	if (!buf)
		return;

	// memset(buf, 0, sizeof(*cp) + sizeof(ad) + sizeof(scan_rsp));
	memset(buf, 0, sizeof(*cp) + sizeof(ad));
	cp = buf;
	cp->instance = 0x01;
	cp->flags = cpu_to_le32(0);
	cp->duration = cpu_to_le16(0);
	cp->timeout = cpu_to_le16(0);
	cp->adv_data_len = sizeof(ad);
	cp->scan_rsp_len = 0;
	// cp->scan_rsp_len = sizeof(scan_rsp);
	memcpy(cp->data, ad, sizeof(ad));
	// memcpy(cp->data + cp->adv_data_len, scan_rsp, cp->scan_rsp_len);
	// mgmt_send_wrapper(mgmt, MGMT_OP_ADD_ADVERTISING, index,
	// 		sizeof(*cp) + sizeof(ad) + sizeof(scan_rsp), buf, NULL, NULL, NULL);
	mgmt_send_wrapper(mgmt, MGMT_OP_ADD_ADVERTISING, index,
			sizeof(*cp) + sizeof(ad), buf, NULL, NULL, NULL);
	free(buf);
}

#if 0
static void enable_advertising(uint16_t index)
{
	uint8_t val;

	val = require_connectable ? 0x01 : 0x00;
	mgmt_send_wrapper(mgmt, MGMT_OP_SET_CONNECTABLE, index, 1, &val,
						NULL, NULL, NULL);

	val = 0x01;
	mgmt_send_wrapper(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
						NULL, NULL, NULL);

	LOGD("adv_instances = %d", adv_instances);
	
	// if (adv_instances) {

	// 	add_advertising(index);
	// 	return;
	// }

	// val = require_connectable ? 0x01 : 0x02;
	// mgmt_send_wrapper(mgmt, MGMT_OP_SET_ADVERTISING, index, 1, &val,
	// 					NULL, NULL, NULL);
}
#endif

static void new_settings_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("New settings");
}

static void local_name_changed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Local name changed");
}

static void new_long_term_key_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("New long term key");
}

static void device_connected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Device connected");
	event_callback(MGMT_EV_DEVICE_CONNECTED, index, length, param, user_data);
}

static void device_disconnected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Device disconnected");
	event_callback(MGMT_EV_DEVICE_DISCONNECTED, index, length, param, user_data);
}

static void user_confirm_request_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("User confirm request");
}

static void user_passkey_request_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("User passkey request");
}

static void auth_failed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Authentication failed");
}

static void device_unpaired_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Device unpaired");
}

static void passkey_notify_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Passkey notification");
}

static void new_irk_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("New identify resolving key");
}

static void new_csrk_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("New connection signature resolving key");
}

static void new_conn_param_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("New connection parameter");
	event_callback(MGMT_EV_NEW_CONN_PARAM, index, length, param, user_data);
}

static void advertising_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Advertising added");
}

static void advertising_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Advertising removed");
}

static size_t bin2hex(const uint8_t *buf, size_t buflen, char *str,
								size_t strlen)
{
	size_t i;

	for (i = 0; i < buflen && i < (strlen / 2); i++)
		sprintf(str + (i * 2), "%02x", buf[i]);

	return i;
}

static char * system_config_type_str(uint16_t type)
{
	switch(type) {
		case 0x0000:
			return "BR/EDR Page Scan Type";
		case 0x0001:
			return "BR/EDR Page Scan Interval";
		case 0x0002:
			return "BR/EDR Page Scan Window";
		case 0x0003:
			return "BR/EDR Inquiry Scan Type";
		case 0x0004:
			return "BR/EDR Inquiry Scan Interval";
		case 0x0005:
			return "BR/EDR Inquiry Scan Window";
		case 0x0006:
			return "BR/EDR Link Supervision Timeout";
		case 0x0007:
			return "BR/EDR Page Timeout";
		case 0x0008:
			return "BR/EDR Min Sniff Interval";
		case 0x0009:
			return "BR/EDR Max Sniff Interval";
		case 0x000a:
			return "LE Advertisement Min Interval";
		case 0x000b:
			return "LE Advertisement Max Interval";
		case 0x000c:
			return "LE Multi Advertisement Rotation Interval";
		case 0x000d:
			return "LE Scanning Interval for auto connect";
		case 0x000e:
			return "LE Scanning Window for auto connect";
		case 0x000f:
			return "LE Scanning Interval for wake scenarios";
		case 0x0010:
			return "LE Scanning Window for wake scenarios";
		case 0x0011:
			return "LE Scanning Interval for discovery";
		case 0x0012:
			return "LE Scanning Window for discovery";
		case 0x0013:
			return "LE Scanning Interval for adv monitoring";
		case 0x0014:
			return "LE Scanning Window for adv monitoring";
		case 0x0015:
			return "LE Scanning Interval for connect";
		case 0x0016:
			return "LE Scanning Window for connect";
		case 0x0017:
			return "LE Min Connection Interval";
		case 0x0018:
			return "LE Max Connection Interval";
		case 0x0019:
			return "LE Connection Latency";
		case 0x001a:
			return "LE Connection Supervision Timeout";
		case 0x001b:
			return "LE Autoconnect Timeout";
		default:
			return "unkonw";
	}
}

static void print_mgmt_tlv(void *data, void *user_data)
{
	const struct mgmt_tlv *entry = data;
	char buf[256];

	bin2hex(entry->value, entry->length, buf, sizeof(buf));
	LOGD("Type: 0x%04x\tLength: %02hhu\tValue: %s\tName: %s", entry->type, entry->length,
							buf, system_config_type_str(entry->type));
}

static void set_sysconfig_rsp(uint8_t status, uint16_t len, const void *param,
								void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		LOGE("Could not set default system configuration with status "
				"0x%02x (%s)", status, mgmt_errstr(status));
	}

	// LOGD("Set default system configuration: success");
}

static void set_sysconfig_item(uint16_t type, uint8_t length, uint8_t value[])
{
	struct mgmt_tlv_list *tlv_list = NULL;

	tlv_list = mgmt_tlv_list_new();

	if (!tlv_list) {
		LOGE("tlv_list failed to init");
		return;
	}

	if (!mgmt_tlv_add(tlv_list, type, length, value)) {
		LOGE("failed to add");
		return;
	}

	mgmt_send_tlv_wrapper(mgmt, MGMT_OP_SET_DEF_SYSTEM_CONFIG, mgmt_index,
				tlv_list, set_sysconfig_rsp, NULL, NULL);

	if (tlv_list)
		mgmt_tlv_list_free(tlv_list);
}

static void set_sysconfig_adv_param(uint16_t adv_max_interval, uint16_t adv_min_interval)
{
	char value[256] = {0x00};

	/* set adv max interval */
	value[0] = 0x00;
	value[1] = 0x01;
	set_sysconfig_item(0x000a, 0x02, value);

	/* set adv min interval */
	value[0] = 0x00;
	value[1] = 0x01;
	set_sysconfig_item(0x000b, 0x02, value);
}

static void read_sysconfig_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	struct mgmt_tlv_list *tlv_list;

	if (status != 0) {
		LOGE("Read system configuration failed with status "
				"0x%02x (%s)", status, mgmt_errstr(status));
		return;
	}

	tlv_list = mgmt_tlv_list_load_from_buf(param, len);
	if (!tlv_list) {
		LOGE("Unable to parse response of read system configuration");
		return;
	}

	LOGD("Default System Config:");
	mgmt_tlv_list_foreach(tlv_list, print_mgmt_tlv, NULL);
	mgmt_tlv_list_free(tlv_list);
	
	cmd_callback(MGMT_OP_READ_DEF_SYSTEM_CONFIG, status, len, param, user_data);

	// bthost = hciemu_client_get_host(hciemu_stack);
	// bthost_set_scan_params(bthost, 0x01, 0x00, 0x00);
	// bthost_set_scan_enable(bthost, 0x01);
}

static void reset_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	LOGD("reset complete");
	
	cmd_callback(MGMT_OP_SET_POWERED, status, len, param, user_data);

	// enable_advertising(index);
	mgmt_send_wrapper(mgmt, MGMT_OP_READ_DEF_SYSTEM_CONFIG, mgmt_index, 0, NULL,
					read_sysconfig_rsp, NULL, NULL);
}

static void read_adv_features_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_adv_features *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	uint32_t flags;
	uint8_t val = 0;

	flags = le32_to_cpu(rp->supported_flags);

	cmd_callback(MGMT_OP_READ_ADV_FEATURES, status, len, param, user_data);

	LOGD("Read Adv Features Complete: max_instances(%d) num_instances(%d) flags(%08x)", rp->max_instances, rp->num_instances, flags);

	if (rp->max_instances > 0) {
		adv_instances = true;
		if (flags & MGMT_ADV_FLAG_CONNECTABLE)
			require_connectable = true;
	} else
		require_connectable = false;

	for (int i = 0; i < rp->num_instances; i ++) {
		struct mgmt_cp_remove_advertising cmd = { 0x00 };
		cmd.instance = rp->instance[i];

		mgmt_send_wrapper(mgmt, MGMT_OP_REMOVE_ADVERTISING, mgmt_index, 1, &cmd,
					NULL, NULL, NULL);
	}
	
	val = 0x01;
	mgmt_send_wrapper(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
							reset_complete, UINT_TO_PTR(mgmt_index), NULL);
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
		LOGE("Reading info for index %u failed: %s",
						index, mgmt_errstr(status));
		return;
	}

	supported_settings = le32_to_cpu(rp->supported_settings);
	current_settings = le32_to_cpu(rp->current_settings);

	if ((supported_settings & required_settings) != required_settings) {
		LOGE("index %d doesn't support BLE Features ", index);
		return;
	}

	if ((mgmt_index != MGMT_INDEX_NONE) && (mgmt_index != index)) {
		LOGE("Selecting index %u already", mgmt_index);
		return;
	}

	LOGD("Selecting index %u", index);

	mgmt_index = index;

	memcpy(static_addr, (uint8_t *)&rp->bdaddr, 6);

	mgmt_register(mgmt, MGMT_EV_NEW_SETTINGS, index,
					new_settings_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_LOCAL_NAME_CHANGED, index,
					local_name_changed_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_LONG_TERM_KEY, index,
					new_long_term_key_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_CONNECTED, index,
					device_connected_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_DISCONNECTED, index,
					device_disconnected_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_USER_CONFIRM_REQUEST, index,
					user_confirm_request_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_USER_PASSKEY_REQUEST, index,
					user_passkey_request_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_AUTH_FAILED, index,
					auth_failed_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_UNPAIRED, index,
					device_unpaired_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_PASSKEY_NOTIFY, index,
					passkey_notify_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_IRK, index,
					new_irk_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_CSRK, index,
					new_csrk_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_CONN_PARAM, index,
					new_conn_param_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_ADVERTISING_ADDED, index,
					advertising_added_event, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_ADVERTISING_REMOVED, index,
					advertising_removed_event, NULL, NULL);

	dev_name_len = snprintf((char *) dev_name, 26, "uhos gatt-server");

	if (current_settings & MGMT_SETTING_POWERED) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (!(current_settings & MGMT_SETTING_LE)) {
		val = 0x01;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_LE, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_CONNECTABLE) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_CONNECTABLE, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_BREDR) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_BREDR, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_SECURE_CONN) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_DEBUG_KEYS) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
							NULL, NULL, NULL);
	}

	/* disable bond support. */
	if ((current_settings & MGMT_SETTING_BONDABLE)) {
		val = 0x00;
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_BONDABLE, index, 1, &val,
							NULL, NULL, NULL);
	}

	clear_long_term_keys(mgmt_index);
    clear_identity_resolving_keys(mgmt_index);


	mgmt_send_wrapper(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index,
	 				6, static_addr, NULL, NULL, NULL);

	// mgmt_send_wrapper(mgmt, MGMT_OP_SET_LOCAL_NAME, index,
	// 				260, dev_name, NULL, NULL, NULL);

	gatt_set_static_address(static_addr);
	gatt_set_device_name(dev_name, dev_name_len);

	gatt_server_start();

	if (adv_features)	
		mgmt_send_wrapper(mgmt, MGMT_OP_READ_ADV_FEATURES, mgmt_index, 0, NULL,
						read_adv_features_complete,
						UINT_TO_PTR(mgmt_index), NULL);
}

static void read_index_list_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t count;
	int i;

	cmd_callback(MGMT_OP_READ_INDEX_LIST, status, len, param, user_data);

	if (status) {
		LOGE("Reading index list failed: %s",
						mgmt_errstr(status));
		return;
	}

	count = le16_to_cpu(rp->num_controllers);

	LOGD("Index list: %u", count);

	if (mgmt_index != MGMT_INDEX_NONE) {
		/* App select mgmt index*/
		mgmt_send_wrapper(mgmt, MGMT_OP_READ_INFO, mgmt_index, 0, NULL,
				read_info_complete, UINT_TO_PTR(mgmt_index), NULL);
	} else {
		/* Select first support le feature controller */
		for (i = 0; i < count; i++) {
			uint16_t index = cpu_to_le16(rp->index[i]);
			mgmt_send_wrapper(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
					read_info_complete, UINT_TO_PTR(index), NULL);
		}
	}
}

static void index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Index added");

	if (mgmt_index != MGMT_INDEX_NONE)
		return;

	mgmt_send_wrapper(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
}

static void index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Index removed");

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
		LOGE("Reading extended index list failed: %s",
						mgmt_errstr(status));
		return;
	}

	count = le16_to_cpu(rp->num_controllers);

	LOGD("Extended index list: %u", count);

	for (i = 0; i < count; i++) {
		uint16_t index = cpu_to_le16(rp->entry[i].index);

		mgmt_send_wrapper(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
	}
}

static void ext_index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_ext_index_added *ev = param;

	LOGD("Extended index added: %u", ev->type);

	if (mgmt_index != MGMT_INDEX_NONE)
		return;

	if (ev->type != 0x00)
		return;

	mgmt_send_wrapper(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
				read_info_complete, UINT_TO_PTR(index), NULL);
}

static void ext_index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_ext_index_added *ev = param;

	LOGD("Extended index removed: %u", ev->type);

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
		LOGE("Reading index list failed: %s",
						mgmt_errstr(status));
		return;
	}

	num_commands = le16_to_cpu(rp->num_commands);

	LOGD("Support %d commands:", num_commands);

	for (i = 0; i < num_commands; i++) {
		uint16_t op = get_le16(rp->opcodes + i);
		
		LOGD("opcode = %04x(%s)", op, opcode_str(op));

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

	// 	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_EXT_INDEX_LIST,
	// 			MGMT_INDEX_NONE, 0, NULL,
	// 			read_ext_index_list_complete, NULL, NULL)) {
	// 		LOGE("Failed to read extended index list");
	// 		return;
	// 	}
	// } else 
	// {
	mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
				index_added_event, NULL, NULL);

	mgmt_register(mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
				index_removed_event, NULL, NULL);
												
	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_INDEX_LIST,
			MGMT_INDEX_NONE, 0, NULL,
			read_index_list_complete, NULL, NULL)) {
		LOGE("Failed to read index list");
		return;
	}
	// }
}

static void read_version_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_version *rp = param;

	LOGD("Reading management Version Information: version(%d) revision(%d)", rp->version, rp->revision);

	cmd_callback(MGMT_OP_READ_VERSION, status, len, param, user_data);

	if(status) {
		LOGE("Reading version failed: %s", mgmt_errstr(status));
	}

	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_COMMANDS,
				MGMT_INDEX_NONE, 0, NULL,
				read_commands_complete, NULL, NULL)) {
		LOGE("Failed to read supported commands");
		return;
	}
}

static const char *get_adv_pdu_type(uint16_t adv_type)
{
	const char *str;
	switch (adv_type)
	{
		case 0x00:
			str = "ADV_IND";
			break;
		case 0x01:
			str = "ADV_DIRECT_IND";
			break;
		case 0x02:
			str = "ADV_SCAN_IND";
			break;
		case 0x03:
			str = "ADV_NONCONN_IND";
			break;
		default:
			str = "Reserved";
			break;
	}
	return str;
}

static void advertising_rm_adv(uint8_t instance)
{
	struct mgmt_cp_remove_advertising cmd = {0x00};
	cmd.instance = instance;
	mgmt_send_sync(mgmt, MGMT_OP_REMOVE_ADVERTISING, mgmt_index, sizeof(cmd), &cmd, NULL);
	g_adv_running = false;
}

static void advertising_add_adv(uint8_t adv_type, uint8_t instance, uint8_t * adv_data, uint8_t adv_len,
									uint8_t * scan_rsp, uint8_t scan_rsp_len)
{
	struct mgmt_cp_add_advertising *cp;
	void *buf;

	buf = malloc(sizeof(*cp) + adv_len + scan_rsp_len);
	if (!buf)
		return;

	memset(buf, 0, sizeof(*cp) + adv_len + scan_rsp_len);

	cp = buf;
	cp->instance = instance;
	
	g_adv_type = adv_type;

	if (adv_type == ADV_NONCONN_IND) 
		cp->flags = cpu_to_le32(0);
	else
		cp->flags = cpu_to_le32(MGMT_ADV_FLAG_CONNECTABLE);

	cp->duration = cpu_to_le16(0);
	cp->timeout = cpu_to_le16(0);
	cp->adv_data_len = adv_len;
	cp->scan_rsp_len = scan_rsp_len;

	memcpy(cp->data, adv_data, adv_len);
	memcpy(cp->data + adv_len, scan_rsp, scan_rsp_len);

	mgmt_send_sync(mgmt, MGMT_OP_ADD_ADVERTISING, mgmt_index,
			sizeof(*cp) + adv_len + scan_rsp_len, buf, NULL);

	g_adv_running = true;
	
	free(buf);
}

static const char *typestr(uint8_t type)
{
	static const char *str[] = { "BR/EDR", "LE Public", "LE Random" };

	if (type <= BDADDR_LE_RANDOM)
		return str[type];

	return "(unknown)";
}

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len)
{
	uint8_t parsed = 0;

	if (eir_len < 2)
		return NULL;

	while (parsed < eir_len - 1) {
		uint8_t field_len = eir[0];

		if (field_len == 0)
			break;

		parsed += field_len + 1;

		if (parsed > eir_len)
			break;

		/* Check for short of complete name */
		if (eir[1] == 0x09 || eir[1] == 0x08)
			return strndup((char *) &eir[2], field_len - 1);

		eir += field_len + 1;
	}

	return NULL;
}

static unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len)
{

	uint8_t parsed = 0;

	if (eir_len < 2)
		return 0;

	while (parsed < eir_len - 1) {
		uint8_t field_len = eir[0];

		if (field_len == 0)
			break;

		parsed += field_len + 1;

		if (parsed > eir_len)
			break;

		/* Check for flags */
		if (eir[1] == 0x01)
			return eir[2];

		eir += field_len + 1;
	}

	return 0;
}

static void device_found(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_found *ev = param;
	uint16_t eir_len;
	uint32_t flags;

	if (len < sizeof(*ev)) {
		LOGE("Too short device_found length (%u bytes)", len);
		return;
	}

	flags = btohl(ev->flags);

	eir_len = get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		LOGE("dev_found: expected %zu bytes, got %u bytes",
						sizeof(*ev) + eir_len, len);
		return;
	}

	char addr[18], *name;

	ba2str(&ev->addr.bdaddr, addr);
	LOGD("hci%u dev_found: %s type %s rssi %d "
		"flags 0x%04x(%s) ", index, addr,
		typestr(ev->addr.type), ev->rssi, flags, flags & MGMT_DEV_FOUND_NOT_CONNECTABLE ? "non_connectable" : "connectable");

	if (ev->addr.type != BDADDR_BREDR)
		LOGD("AD flags 0x%02x ",
				eir_get_flags(ev->eir, eir_len));

	name = eir_get_name(ev->eir, eir_len);
	if (name)
		LOGD("name %s", name);
	else
		LOGD("eir_len %u", eir_len);

	free(name);

	event_callback(MGMT_EV_DEVICE_FOUND, index, len, param, user_data);
}

static unsigned int discovery_id = -1;

static void start_discovery()
{
	struct mgmt_cp_start_discovery cp;
	cp.type = (1 << BDADDR_LE_PUBLIC)|(1 << BDADDR_LE_RANDOM);

	mgmt_send_wrapper(mgmt, MGMT_OP_START_DISCOVERY,
				mgmt_index, sizeof(cp), &cp,
				NULL, NULL, NULL);

	discovery_id = mgmt_register(mgmt, MGMT_EV_DEVICE_FOUND, mgmt_index, device_found,
								NULL, NULL);
}

static void stop_discovery()
{
	struct mgmt_cp_stop_discovery cp;
	cp.type = (1 << BDADDR_LE_PUBLIC)|(1 << BDADDR_LE_RANDOM);

	mgmt_send_wrapper(mgmt, MGMT_OP_STOP_DISCOVERY,
				mgmt_index, sizeof(cp), &cp,
				NULL, NULL, NULL);

	if (discovery_id != -1)
		mgmt_unregister(mgmt, discovery_id);
}

static void set_sysconfig_scan_param(uint16_t scan_interval, uint16_t scan_window)
{
	char value[256] = {0x00};

	/* set scan interval */
	value[0] = 0x00;
	value[1] = 0x01;
	set_sysconfig_item(0x0011, 0x02, value);

	/* set scan window */
	value[0] = 0x00;
	value[1] = 0x01;
	set_sysconfig_item(0x0012, 0x02, value);
}

/*
	this function is for mgmt's bug that when adv data is not changed, restart adv is not work.
*/
static void advertising_add_empty_adv(uint8_t adv_type, uint8_t instance)
{
	uint8_t adv_data[] = {0x02, 0x01, 0x06};
	uint8_t scan_rsp_data[] = {0x06, 0x09, 'e', 'm', 'p', 't', 'y'};
	advertising_add_adv(adv_type, instance, adv_data, sizeof(adv_data), scan_rsp_data, sizeof(scan_rsp_data));
}

void bluez_gap_set_adv_data(uint8_t const * adv, uint8_t adv_len, uint8_t const * scan_rsp, uint8_t scan_rsp_len) 
{
	memset(g_adv_data, 0x00, ADV_MAX_LENGTH);
	memset(g_scan_rsp, 0x00, ADV_MAX_LENGTH);
	g_adv_data_len = 0;
	g_scan_rsp_len = 0;

	if (adv_len > 0) {
		uint8_t adv_len_t = 0;
		adv_len_t = (adv_len <= ADV_MAX_LENGTH) ? adv_len : ADV_MAX_LENGTH;
		memcpy(g_adv_data, adv, adv_len_t);
		g_adv_data_len = adv_len_t;
	}

	if (scan_rsp_len > 0) {
		uint8_t scan_rsp_len_t = 0;
		scan_rsp_len_t = (scan_rsp_len <= ADV_MAX_LENGTH) ? scan_rsp_len : ADV_MAX_LENGTH;
		memcpy(g_scan_rsp, scan_rsp, scan_rsp_len_t);
		g_scan_rsp_len = scan_rsp_len_t;
	}

	if (g_adv_running == true) {
		/* advertising is running, only update adv data */
		advertising_add_adv(g_adv_type, 0x01, g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
	}
}

void bluez_gap_set_adv_start(uint8_t adv_type, uint16_t max_interval, uint16_t min_interval)
{
	LOGD("%s(%02x) max_interval(%02x) min_interval(%02x)", 
								get_adv_pdu_type(adv_type), adv_type, max_interval, min_interval);

	set_sysconfig_adv_param(max_interval, min_interval);
	advertising_add_adv(adv_type, 0x01, g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
}

void bluez_gap_set_adv_stop()
{
	advertising_add_empty_adv(g_adv_type, 0x01);
	advertising_rm_adv(0x01);
}

void bluez_gap_set_adv_restart()
{
	advertising_add_empty_adv(g_adv_type, 0x01);
	advertising_rm_adv(0x01);
	advertising_add_adv(g_adv_type, 0x01, g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
}

void bluez_gap_set_scan_start(uint8_t scan_type, uint16_t scan_interval, uint16_t scan_window,
								uint16_t timeout)
{
	set_sysconfig_scan_param(scan_interval, scan_window);
	start_discovery();
}

void bluez_gap_set_scan_stop()
{
	stop_discovery();
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
	LOGD("Using static address %02x:%02x:%02x:%02x:%02x:%02x",
			static_addr[5], static_addr[4], static_addr[3],
			static_addr[2], static_addr[1], static_addr[0]);
}

void bluez_gap_register_callback(bluez_gap_cmd_callback_func cmd_cb, bluez_gap_event_callback_func event_cb)
{
	g_cmd_cb = cmd_cb;
	g_event_cb = event_cb;
}

// static void print_debug(const char *str, void *user_data)
// {
// 	const char *prefix = user_data;

// 	LOGI("%s%s", prefix, str);
// }

// static void client_cmd_complete(uint16_t opcode, uint8_t status,
// 					const void *param, uint8_t len,
// 					void *user_data)
// {
// 	LOGW("***************** opcode = %04x", opcode);
// 	return;
// }


// static void command_hci_callback(uint16_t opcode, const void *param,
// 					uint8_t length, void *user_data)
// {
// 	LOGE("HCI Command 0x%04x length %u", opcode, length);
// }

// static bool hook_callback(const void *data, uint16_t len,
// 							void *user_data)
// {
// 	LOG_HEXDUMP_DBG(data, len, "hook_callback");
// }

void bluez_gap_init(void)
{
	mgmt = mgmt_new_default();
	if (!mgmt) {
		LOGE("Failed to open management socket");
		return;
	}

	// hciemu_stack = hciemu_new(HCIEMU_TYPE_LE);

	// hciemu_set_debug(hciemu_stack, print_debug, "hciemu: ", NULL);

	// bthost = hciemu_client_get_host(hciemu_stack);
	// bthost_set_cmd_complete_cb(bthost, client_cmd_complete, NULL);

	// hciemu_add_central_post_command_hook(hciemu_stack,
	// 		command_hci_callback, NULL);

	// hciemu_add_hook(hciemu_stack, HCIEMU_HOOK_POST_CMD,
	// 		BT_HCI_CMD_LE_SET_ADV_ENABLE,
	// 		hook_callback, NULL);

	return ;
}

void bluez_gap_adapter_init(uint16_t hci_index)
{
	mgmt_index = hci_index;

	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_VERSION,
				MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, NULL, NULL)) {
		LOGE("Failed to read version");
		return;
	}
}

void bluez_gap_uinit(void)
{
	if (!mgmt)
		return;

	// gatt_server_stop();

    mgmt_unref(mgmt);
	mgmt = NULL;

	mgmt_index = MGMT_INDEX_NONE;

	gatt_server_stop();

	// hciemu_unref(hciemu_stack);
	// hciemu_stack = NULL;
}

// void bluez_gap_test() 
// {
// 	sem_t semaphore;
// 	sem_init(&semaphore, 0, 1);
// 	sem_wait(&semaphore);
// 	sem_post((sem_t *)user_data)
// 	sem_destroy(&semaphore);
// 	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_VERSION,
// 				MGMT_INDEX_NONE, 0, NULL,
// 				read_version_complete, &semaphore, NULL)) {
// 		LOGE("Failed to read version");
// 		return;
// 	}

// 	sem_wait(&semaphore);

// 	if (!mgmt_send_wrapper(mgmt, MGMT_OP_READ_COMMANDS,
// 				MGMT_INDEX_NONE, 0, NULL,
// 				read_commands_complete, NULL, NULL)) {
// 		LOGE("Failed to read supported commands");
// 		return;
// 	}

// 	// if (user_data != NULL)
// 	// 	sem_post((sem_t *)user_data);

// 	sem_destroy(&semaphore);
// }
