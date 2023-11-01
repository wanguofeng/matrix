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
#include <sys/eventfd.h>
#include <semaphore.h>
#include <time.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>


#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"

#include "lib/mgmt.h"
#include "src/shared/mgmt.h"
#include "peripheral/gatt.h"
#include "peripheral/gap.h"
#include "peripheral/utils.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#define CONFIG_LOG_TAG "Bluez_Stack"
#include "peripheral/log.h"

#define ADV_MAX_LENGTH	31

#define HCI_VERSION_4_1	0x07
#define HCI_VERSION_4_2	0x08
#define HCI_VERSION_5_0	0x09
#define HCI_VERSION_5_1	0x0A
#define HCI_VERSION_5_2	0x0B
#define HCI_VERSION_5_3	0x0C
#define HCI_VERSION_5_4	0x0D

static int event_fd = 0;
static uint32_t pre_current_settings = 0;

static struct queue *pending_cmd_list = NULL;
static struct queue *pending_cmd_tlv_list = NULL;
static struct queue *pending_gatts_list = NULL;

static struct mgmt *mgmt = NULL;
static uint16_t mgmt_index = MGMT_INDEX_NONE;
static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;


static bool adv_features = false;
static bool adv_instances = false;
static bool require_connectable = true;
static unsigned int discovery_id = -1;

static uint8_t static_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0 };
static uint8_t public_addr[6] = { 0x00};
static uint8_t dev_name[260] = { 0x00, };
static uint8_t dev_name_len = 0;

static uint8_t g_adv_type = 0;
static uint16_t g_min_interval = 0;
static uint16_t g_max_interval = 0;
static uint8_t g_adv_running = false;
static uint8_t g_adv_data[ADV_MAX_LENGTH] = {0x00};
static uint8_t g_adv_data_len = 0;
static uint8_t g_scan_rsp[ADV_MAX_LENGTH] = {0x00};
static uint8_t g_scan_rsp_len = 0;

static bool mgmt_low_version = false;
static bool hci_low_version = false;

static bluez_gap_event_callback_func g_event_cb = NULL;
static bluez_gap_cmd_callback_func g_cmd_cb = NULL;

static void recv_cmd(int fd, uint32_t events, void *user_data);

struct send_sync {
	sem_t sem;
	uint16_t opcode;
	uint8_t status;
	void *userdata;
};

typedef struct _mgmt_send_async {
	struct mgmt *mgmt;
	uint16_t opcode;
	uint16_t index;
	uint16_t length;
	void *param;
	mgmt_request_func_t callback;
	void *user_data;
	mgmt_destroy_func_t destroy;
} mgmt_send_async;

typedef struct _mgmt_send_tlv_async {
	struct mgmt *mgmt;
	uint16_t opcode;
	uint16_t index;
	struct mgmt_tlv_list *tlv_list;
	mgmt_request_func_t callback;
	void *user_data;
	mgmt_destroy_func_t destroy;
} mgmt_send_tlv_async;

typedef struct _gatts_send_async {
	uint16_t conn_handle;
	uint16_t srv_handle;
	uint16_t char_value_handle;
	uint8_t offset;
	uint8_t *p_value;
	uint16_t len;
} gatts_send_async;

static int8_t mgmt_send_wrapper(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				uint16_t length, const void *param,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	mgmt_send_async *mgmt_cmd = malloc(sizeof(mgmt_send_async));

	mgmt_cmd->mgmt = mgmt;
	mgmt_cmd->opcode = opcode;
	mgmt_cmd->index = index;
	mgmt_cmd->length = length;
	mgmt_cmd->param = param;
	mgmt_cmd->callback = callback;
	mgmt_cmd->user_data = user_data;
	mgmt_cmd->destroy = destroy;

	if (!queue_push_tail(pending_cmd_list, mgmt_cmd)) {
		LOGE("add to pending_cmd_list failed");
	}

	int ret = eventfd_write(event_fd, 1);
	if (ret < 0) {
		LOGE("write event fd fail:%s", strerror(errno));
		return -1;
	}

	return 0;
}

static int8_t mgmt_send_tlv_wrapper(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				struct mgmt_tlv_list *tlv_list,
				mgmt_request_func_t callback,
				void *user_data, mgmt_destroy_func_t destroy)
{
	mgmt_send_tlv_async *mgmt_send_tlv = malloc(sizeof(mgmt_send_tlv_async));

	mgmt_send_tlv->mgmt = mgmt;
	mgmt_send_tlv->opcode = opcode;
	mgmt_send_tlv->index = index;
	mgmt_send_tlv->tlv_list = tlv_list;
	mgmt_send_tlv->callback = callback;
	mgmt_send_tlv->user_data = user_data;
	mgmt_send_tlv->destroy = destroy;

	if (!queue_push_tail(pending_cmd_tlv_list, mgmt_send_tlv)) {
		LOGE("add to pending_cmd_tlv_list failed");
	}
	int ret = eventfd_write(event_fd, 1);
	if (ret < 0) {
		LOGE("write event fd fail:%s", strerror(errno));
		return -1;
	}

	return 0;
}

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
	LOGD("length = %d", length);
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


static void index_added_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Index added");

	if (mgmt_index != MGMT_INDEX_NONE)
		return;

	// mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
	// 			read_info_complete, UINT_TO_PTR(index), NULL);
}

static void index_removed_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Index removed");

	if (mgmt_index != index)
		return;

	mgmt_index = MGMT_INDEX_NONE;
}

static void set_sysconfig_rsp(uint8_t status, uint16_t len, const void *param,
								void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		LOGE("Could not set default system configuration with status "
				"0x%02x (%s)", status, mgmt_errstr(status));
	}
}

static void read_sysconfig_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	struct mgmt_tlv_list *tlv_list;

	if (status != 0) {
		LOGW("Read system configuration failed with status "
				"0x%02x (%s)", status, mgmt_errstr(status));
		LOGW("Using hci_lib interface.");

		mgmt_low_version = true;
		cmd_callback(MGMT_OP_READ_DEF_SYSTEM_CONFIG, status, len, param, user_data);
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

}

static void reset_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	LOGD("reset complete");
	
	cmd_callback(MGMT_OP_SET_POWERED, status, len, param, user_data);

	// enable_advertising(index);
	mgmt_send(mgmt, MGMT_OP_READ_DEF_SYSTEM_CONFIG, mgmt_index, 0, NULL,
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
		memset(&cmd, 0, sizeof(cmd));
		cmd.instance = rp->instance[i];

		mgmt_send(mgmt, MGMT_OP_REMOVE_ADVERTISING, mgmt_index, 1, &cmd,
					NULL, NULL, NULL);
	}
	
	val = 0x01;
	mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
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
	uint8_t val = 0;

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
		LOGW("index %d doesn't support BLE Features ", index);
		return;
	}

	if ((mgmt_index != MGMT_INDEX_NONE) && (mgmt_index != index)) {
		LOGE("Selecting index %u already", mgmt_index);
		return;
	}

	LOGD("Selecting index %u, hci_version = %x", index, rp->version);



	if (HCI_VERSION_4_2 >= rp->version) {
		hci_low_version = true;
	}
	
	mgmt_index = index;

	memcpy(public_addr, (uint8_t *)&rp->bdaddr, 6);

	static_addr[0] = rand();
	static_addr[1] = rand();
	static_addr[2] = rand();
	static_addr[3] = rand();
	static_addr[4] = rand();
	static_addr[5] = 0xc0;

	LOGD("generate static addr %02x:%02x:%02x:%02x:%02x:%02x\n", static_addr[5], static_addr[4], static_addr[3],
													  static_addr[2], static_addr[1], static_addr[0]);

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
		mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (!(current_settings & MGMT_SETTING_LE)) {
		val = 0x01;
		mgmt_send(mgmt, MGMT_OP_SET_LE, index, 1, &val,
							NULL, NULL, NULL);
	}

	pre_current_settings = current_settings;

#if 1
	if (current_settings & MGMT_SETTING_CONNECTABLE) {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_CONNECTABLE, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_BREDR) {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_BREDR, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_SECURE_CONN) {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_DEBUG_KEYS) {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
							NULL, NULL, NULL);
	}

	/* disable bond support. */
	if ((current_settings & MGMT_SETTING_BONDABLE)) {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_BONDABLE, index, 1, &val,
							NULL, NULL, NULL);
	}

	clear_long_term_keys(mgmt_index);
    clear_identity_resolving_keys(mgmt_index);
#endif

	mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index,
	 				6, static_addr, NULL, NULL, NULL);

	// mgmt_send(mgmt, MGMT_OP_SET_LOCAL_NAME, index,
	// 				260, dev_name, NULL, NULL, NULL);

	bluez_gatts_set_static_address(static_addr);
	bluez_gatts_set_device_name(dev_name, dev_name_len);

	mainloop_add_fd(event_fd, EPOLLIN, recv_cmd, NULL, NULL);

	if (adv_features)	
		mgmt_send(mgmt, MGMT_OP_READ_ADV_FEATURES, mgmt_index, 0, NULL,
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

	mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
				index_added_event, NULL, NULL);

	mgmt_register(mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
				index_removed_event, NULL, NULL);
												
	if (!mgmt_send(mgmt, MGMT_OP_READ_INDEX_LIST,
			MGMT_INDEX_NONE, 0, NULL,
			read_index_list_complete, NULL, NULL)) {
		LOGE("Failed to read index list");
		return;
	}
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

	if (!mgmt_send(mgmt, MGMT_OP_READ_COMMANDS,
				MGMT_INDEX_NONE, 0, NULL,
				read_commands_complete, NULL, NULL)) {
		LOGE("Failed to read supported commands");
		return;
	}
}

static void get_conn_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_conn_info *rp = param;
	char addr[18];

	struct send_sync *sync = user_data;

	sync->status = status;
	memcpy(sync->userdata, param, len);
	sem_post(&sync->sem);

	if (len == 0 && status != 0) {
		LOGE("Get Conn Info failed, status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return;
	}

	if (len < sizeof(*rp)) {
		LOGE("Unexpected Get Conn Info len %u", len);
		return;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status) {
		LOGE("Get Conn Info for %s (%s) failed. status 0x%02x (%s)",
						addr, typestr(rp->addr.type),
						status, mgmt_errstr(status));
	} else {
		LOGD("Connection Information for %s (%s)",
						addr, typestr(rp->addr.type));
		LOGD("\tRSSI %d\tTX power %d\tmaximum TX power %d",
				rp->rssi, rp->tx_power, rp->max_tx_power);
	}
}

static void set_disconnect_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_disconnect *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		LOGE("Disconnect failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return;
	}

	if (len != sizeof(*rp)) {
		LOGE("Invalid disconnect response length (%u)", len);
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status == 0)
		LOGD("%s disconnected", addr);
	else
		LOGE("Disconnecting %s failed with status 0x%02x (%s)",
				addr, status, mgmt_errstr(status));

	cmd_callback(MGMT_OP_DISCONNECT, status, len, param, user_data);
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

	// if (tlv_list)
	// 	mgmt_tlv_list_free(tlv_list);
}

static void advertising_set_adv_param(uint16_t adv_max_interval, uint16_t adv_min_interval)
{
	char value[256] = {0x00};

	/* set adv max interval */
	value[0] = le16(adv_max_interval);
	value[1] = le16((adv_max_interval >> 8));

	set_sysconfig_item(0x000a, 0x02, value);

	/* set adv min interval */
	value[0] = le16(adv_min_interval);
	value[1] = le16((adv_min_interval >> 8));
	set_sysconfig_item(0x000b, 0x02, value);
}

static void advertising_rm_adv(uint8_t instance)
{
	struct mgmt_cp_remove_advertising *cp = malloc(sizeof(*cp));
	memset(cp, 0x00, sizeof(*cp));

	cp->instance = instance;
	mgmt_send_wrapper(mgmt, MGMT_OP_REMOVE_ADVERTISING,
				mgmt_index, sizeof(*cp), cp,
				NULL, NULL, NULL);
	g_adv_running = false;
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

	mgmt_send_wrapper(mgmt, MGMT_OP_ADD_ADVERTISING, mgmt_index,
			sizeof(*cp) + adv_len + scan_rsp_len, buf, NULL, NULL, NULL);

	g_adv_running = true;

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

static void start_scan()
{
	struct mgmt_cp_start_discovery *cp = malloc(sizeof(*cp));

	memset(cp, 0, sizeof(*cp));

	cp->type = (1 << BDADDR_LE_PUBLIC)|(1 << BDADDR_LE_RANDOM);

	mgmt_send_wrapper(mgmt, MGMT_OP_START_DISCOVERY,
				mgmt_index, sizeof(*cp), cp,
				NULL, NULL, NULL);

	discovery_id = mgmt_register(mgmt, MGMT_EV_DEVICE_FOUND, mgmt_index, device_found,
								NULL, NULL);
}

static void stop_scan()
{
	struct mgmt_cp_stop_discovery *cp = malloc(sizeof(*cp));

	memset(cp, 0, sizeof(*cp));

	cp->type = (1 << BDADDR_LE_PUBLIC)|(1 << BDADDR_LE_RANDOM);

	mgmt_send_wrapper(mgmt, MGMT_OP_STOP_DISCOVERY,
				mgmt_index, sizeof(*cp), cp,
				NULL, NULL, NULL);

	if (discovery_id != -1)
		mgmt_unregister(mgmt, discovery_id);
}

static void set_scan_param(uint16_t scan_interval, uint16_t scan_window)
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

static void recv_cmd(int fd, uint32_t events, void *user_data)
{
    if (events & (EPOLLERR | EPOLLHUP)) {
        mainloop_remove_fd(fd);
        return;
    }

    eventfd_t count = 0;
    int ret = eventfd_read(fd, &count);

    if (ret < 0) {
		LOGE("read fail:");
		return;
    }

    // LOGD("eventfd_read count = %ld", count);

	mgmt_send_async * mgmt_cmd = queue_pop_head(pending_cmd_list);
	if (mgmt_cmd != NULL) {
		LOGD("mgmt_send: %s(0x%04x) index(0x%04x)", opcode_str(mgmt_cmd->opcode), mgmt_cmd->opcode, mgmt_cmd->index);
		mgmt_send(mgmt_cmd->mgmt, mgmt_cmd->opcode, mgmt_cmd->index, mgmt_cmd->length, mgmt_cmd->param, 
											mgmt_cmd->callback, mgmt_cmd->user_data, mgmt_cmd->destroy);

		if (mgmt_cmd->param != NULL)
			free(mgmt_cmd->param);

		free(mgmt_cmd);
			return;
	}

	mgmt_send_tlv_async * mgmt_tlv = queue_pop_head(pending_cmd_tlv_list);
	if (mgmt_tlv != NULL) {
		LOGD("mgmt_send_tlv: %s(0x%04x) index(0x%04x)", opcode_str(mgmt_tlv->opcode), mgmt_tlv->opcode, mgmt_tlv->index);
		mgmt_send_tlv(mgmt_tlv->mgmt, mgmt_tlv->opcode, mgmt_tlv->index, mgmt_tlv->tlv_list,
						mgmt_tlv->callback, mgmt_tlv->user_data, mgmt_tlv->destroy);

		if (mgmt_tlv->tlv_list)
			mgmt_tlv_list_free(mgmt_tlv->tlv_list);

		free(mgmt_tlv);
			return;
	}

	gatts_send_async * msg = queue_pop_head(pending_gatts_list);
	if (msg != NULL) {
		if (msg->offset == 0) {
			bluez_gatts_send_notification(msg->char_value_handle, msg->p_value, msg->len);
		} else {
			bluez_gatts_send_indication(msg->char_value_handle, msg->p_value, msg->len);
		}
		free(msg->p_value);
		free(msg);
		return;
	}
}

static void power_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	if (status) {
		LOGE("power off failed: %s\n", mgmt_errstr(status));
	} else {
		LOGI("power off success");
	}
}

static void set_bredr_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	if (status) {
		LOGE("setting BR/EDR failed: %s\n", mgmt_errstr(status));
	} else {
		LOGI("enable BR/EDR success");
	}
}

static void set_le_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	if (status) {
		LOGE("setting LE failed: %s\n", mgmt_errstr(status));
		mainloop_quit();
	} else {
		LOGI("disable LE feature success.");
		mainloop_quit();
	}
}

// static int hci_if_reset_controller()
// {
// 	int device_id = hci_get_route(NULL);

// 	int device_handle = 0;
	
// 	if((device_handle = hci_open_dev(device_id)) < 0)
// 	{
// 		LOGE("Could not open device");
// 		return 1;
// 	}

// 	uint8_t status;
// 	struct hci_request rq;
// 	uint8_t data_length = 0;
// 	memset(&rq, 0, sizeof(rq));

// 	// Reset Controller
// 	rq.ogf = OGF_HOST_CTL;
// 	rq.ocf = OCF_RESET;
// 	rq.cparam = NULL;
// 	rq.clen = 0;
// 	rq.rparam = &status;
// 	rq.rlen = 1;

// 	int ret = hci_send_req(device_handle, &rq, 1000);

// 	if(ret < 0)
// 	{
// 		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
// 		hci_close_dev(device_handle);
// 		return(1);
// 	}

// 	if (status) 
// 	{
// 		LOGE("LE set advertise returned status %d\n", status);
// 		hci_close_dev(device_handle);
// 		return(1);
// 	}

// 	bdaddr_t bdaddr;
// 	char addr[18];

// 	hci_read_bd_addr(device_handle, &bdaddr, 10000);
// 	ba2str(&bdaddr, addr);
// 	LOGW("Controller bdaddr(%s)", addr);

// 	memcpy(static_addr, (uint8_t *)&bdaddr, 6);

// 	hci_close_dev(device_handle);

// 	return 0;
// }

// static void hci_if_set_random_address(uint8_t *addr)
// {
// 	int device_id = hci_get_route(NULL);
// 	uint8_t status;
// 	struct hci_request rq;
// 	int device_handle = 0;

// 	if((device_handle = hci_open_dev(device_id)) < 0)
// 	{
// 		LOGE("Could not open device");
// 		return;
// 	}

//     le_set_random_address_cp cp;

// 	memset(&rq, 0, sizeof(rq));
//     memset(&cp, 0, sizeof(cp)); 
//     memcpy(cp.bdaddr.b, addr, 6); 
//     memset(&rq, 0, sizeof(rq)); 
//     rq.ogf = OGF_LE_CTL; 
//     rq.ocf = OCF_LE_SET_RANDOM_ADDRESS; 
//     rq.cparam = &cp; 
//     rq.clen = LE_SET_RANDOM_ADDRESS_CP_SIZE; 
//     rq.rparam = &status; 
//     rq.rlen = 1; 

// 	int ret = hci_send_req(device_handle, &rq, 1000);

//     if (status || ret < 0) 
//     { 
//         hci_close_dev(device_handle);
// 		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
// 		return;
//     } 
// }

#define OCF_LE_SET_EXTEND_ADVERTISING_PARAMETERS	0x0036
typedef struct {
	uint8_t		handle;
	uint16_t 	properties;
	uint8_t		min_interval[3];
	uint8_t		max_interval[3];
	uint8_t		chan_map;
	uint8_t		own_bdaddr_type;
	uint8_t		direct_bdaddr_type;
	bdaddr_t	direct_bdaddr;
	uint8_t		filter;
	uint8_t		tx_power;
	uint8_t		primary_phy;
	uint8_t		secondary_max_skip;
	uint8_t		secondary_phy;
	uint8_t		sid;
	uint8_t		scan_request_notifications;
} __attribute__ ((packed)) le_set_extend_advertising_parameters_cp;
#define LE_SET_EXTEND_ADVERTISING_PARAMETERS_CP_SIZE 25

#define OCF_LE_SET_EXTEND_ADVERTISING_DATA 			0x0037
typedef struct {
	uint8_t		handle;
	uint8_t		operation;
	uint8_t		fragment;
	uint8_t		length;
	uint8_t		data[31];
} __attribute__ ((packed)) le_set_extend_advertising_data_cp;
#define LE_SET_EXTEND_ADVERTISING_DATA_CP_SIZE 35

#define OCF_LE_SET_EXTEND_SCAN_RESPONSE_DATA		0x0038
typedef struct {
	uint8_t		handle;
	uint8_t		operation;
	uint8_t		fragment;
	uint8_t		length;
	uint8_t		data[31];
} __attribute__ ((packed)) le_set_extend_scan_response_data_cp;
#define LE_SET_EXTEND_SCAN_RESPONSE_DATA_CP_SIZE 35

#define OCF_LE_SET_EXTEND_ADVERTISE_ENABLE		0x0039
typedef struct {
	uint8_t		enable;
	uint8_t		num_sets;
	uint8_t		handle;
	uint16_t	duration;
	uint8_t		max_ext_adv_events;
} __attribute__ ((packed)) le_set_extend_advertise_enable_cp;
#define LE_SET_EXTEND_ADVERTISE_ENABLE_CP_SIZE 6

#define EXTEND_ADV_HANDLE						0x01

#define EXTEND_HCI_ADV_NONCONN_IND				0x0010
#define EXTEND_HCI_ADV_LOW_DUTY_DIRECT_IND		0x0015
#define EXTEND_HCI_ADV_HIGH_DUTY_DIRECT_IND		0x001D
#define EXTEND_HCI_ADV_SCAN_IND					0x0012
#define EXTEND_HCI_ADV_IND						0x0013

static void hci_if_set_scan_rsp(uint8_t * scan_rsp, uint8_t scan_rsp_len)
{
	int device_id = hci_get_route(NULL);
	int ret = 0;
	int device_handle = 0;
	
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		LOGE("Could not open device");
		return;
	}

	uint8_t status;
	struct hci_request rq;
	uint8_t data_length = 0;
	memset(&rq, 0, sizeof(rq));

	if (hci_low_version) {
		// Setup legacy scan response data
		le_set_scan_response_data_cp scan_data_cp;
		memset(&scan_data_cp, 0, sizeof(scan_data_cp));
		memcpy(scan_data_cp.data, scan_rsp, scan_rsp_len);
		scan_data_cp.length = scan_rsp_len;

		LOGD("scan legacy response data[%d]:", scan_data_cp.length);
		for (uint8_t i = 0; i < scan_data_cp.length; i ++) {
			printf("%02x ", scan_data_cp.data[i]);
		}
		printf("\r\n");

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_SCAN_RESPONSE_DATA;
		rq.cparam = &scan_data_cp;
		rq.clen = LE_SET_SCAN_RESPONSE_DATA_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	} else {
		// Setup extend scan response data
		le_set_extend_scan_response_data_cp scan_data_cp;
	
		memset(&scan_data_cp, 0, sizeof(scan_data_cp));
		memcpy(scan_data_cp.data, scan_rsp, scan_rsp_len);

		scan_data_cp.handle = EXTEND_ADV_HANDLE;
		scan_data_cp.operation = 0x03;
		scan_data_cp.fragment = 0x01;
		scan_data_cp.length = scan_rsp_len;

		LOGD("scan extend response data[%d]:", scan_data_cp.length);
		for (uint8_t i = 0; i < scan_data_cp.length; i ++) {
			printf("%02x ", scan_data_cp.data[i]);
		}
		printf("\r\n");

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_EXTEND_SCAN_RESPONSE_DATA;
		rq.cparam = &scan_data_cp;
		rq.clen = LE_SET_EXTEND_SCAN_RESPONSE_DATA_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	}

	ret = hci_send_req(device_handle, &rq, 1000);

	if(ret < 0)
	{
		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
		hci_close_dev(device_handle);
		return(1);
	}

	if (status) 
	{
		LOGE("LE set scan response returned status %d\n", status);
		hci_close_dev(device_handle);
		return(1);
	}

	hci_close_dev(device_handle);
}

static void hci_if_set_advertising_data(uint8_t * adv_data, uint8_t adv_len)
{
	int device_handle = 0;
	int device_id = hci_get_route(NULL);
	int ret = 0;
	
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		LOGE("Could not open device");
		return;
	}

	uint8_t status;
	struct hci_request rq;
	uint8_t data_length = 0;
	memset(&rq, 0, sizeof(rq));

	if (hci_low_version) {
		// Setup legacy advertising data
		le_set_advertising_data_cp adv_data_cp;
		memset(&adv_data_cp, 0, sizeof(adv_data_cp));
		memcpy(adv_data_cp.data, adv_data, adv_len);

		adv_data_cp.length = adv_len;

		LOGD("legacy adv data[%d]: ", adv_data_cp.length);
		for (uint8_t i = 0; i < adv_data_cp.length; i ++) {
			printf("%02x ", adv_data_cp.data[i]);
		}
		printf("\r\n");

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
		rq.cparam = &adv_data_cp;
		rq.clen = 32;
		rq.rparam = &status;
		rq.rlen = 1;
	} else {
		// Setup extend advertising data
		le_set_extend_advertising_data_cp adv_data_cp;
		memset(&adv_data_cp, 0, sizeof(adv_data_cp));
		memcpy(adv_data_cp.data, adv_data, adv_len);

		adv_data_cp.handle = EXTEND_ADV_HANDLE;
		adv_data_cp.operation = 0x03;
		adv_data_cp.fragment = 0x01;
		adv_data_cp.length = adv_len;

		LOGD("extend adv data[%d]: ", adv_data_cp.length);
		for (uint8_t i = 0; i < adv_data_cp.length; i ++) {
			printf("%02x ", adv_data_cp.data[i]);
		}
		printf("\r\n");

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_EXTEND_ADVERTISING_DATA;
		rq.cparam = &adv_data_cp;
		rq.clen = LE_SET_EXTEND_ADVERTISING_DATA_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	}

	ret = hci_send_req(device_handle, &rq, 1000);

	if(ret < 0)
	{
		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
		hci_close_dev(device_handle);
		return(1);
	}

	if (status) 
	{
		LOGE("LE set advertise returned status %d\n", status);
		hci_close_dev(device_handle);
		return(1);
	}

	hci_close_dev(device_handle);
}

static void hci_if_set_adv_enable()
{
	int device_id = hci_get_route(NULL);
	int ret = 0;
	int device_handle = 0;
	
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		LOGE("Could not open device");
		return;
	}

	uint8_t status;
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));

	if (hci_low_version) {
		le_set_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));
		advertise_cp.enable = 0x01;

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
		rq.cparam = &advertise_cp;
		rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	} else {
		le_set_extend_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));

		advertise_cp.enable = 0x01;
		advertise_cp.num_sets = 0x01;
		advertise_cp.handle = EXTEND_ADV_HANDLE;
		advertise_cp.duration = 0x00;
		advertise_cp.max_ext_adv_events = 0x00;
	
		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_EXTEND_ADVERTISE_ENABLE;
		rq.cparam = &advertise_cp;
		rq.clen = LE_SET_EXTEND_ADVERTISE_ENABLE_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	}

	ret = hci_send_req(device_handle, &rq, 1000);

	if (ret < 0)
	{
		hci_close_dev(device_handle);
		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
		return;
	}

	hci_close_dev(device_handle);
}

static void hci_if_set_adv_param(uint8_t adv_type, uint16_t max_interval, uint16_t min_interval)
{
	int device_id = hci_get_route(NULL);
	int ret = 0;
	int device_handle = 0;
	
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		LOGE("Could not open device");
		return;
	}

	uint8_t status;
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));

	if (hci_low_version) {
		le_set_advertising_parameters_cp adv_params_cp;
		memset(&adv_params_cp, 0, sizeof(adv_params_cp));

		adv_params_cp.max_interval = (htobs(max_interval) * 16 / 10);
		adv_params_cp.min_interval = (htobs(min_interval) * 16 / 10);
		adv_params_cp.chan_map = 7;
		adv_params_cp.advtype = adv_type;

		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
		rq.cparam = &adv_params_cp;
		rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	} else {
		le_set_extend_advertising_parameters_cp adv_params_cp;
		memset(&adv_params_cp, 0, sizeof(adv_params_cp));
		uint16_t prop = 0x00;
		adv_params_cp.handle = EXTEND_ADV_HANDLE;

		if (adv_type == UHOS_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED)
			prop = EXTEND_HCI_ADV_IND;
		else if(adv_type == UHOS_BLE_ADV_TYPE_CONNECTABLE_DIRECTED_HDC)
			prop = EXTEND_HCI_ADV_HIGH_DUTY_DIRECT_IND;
		else if(adv_type == UHOS_BLE_ADV_TYPE_SCANNABLE_UNDIRECTED)
			prop = EXTEND_HCI_ADV_SCAN_IND;		
		else if(adv_type == UHOS_BLE_ADV_TYPE_NON_CONNECTABLE_UNDIRECTED)
			prop = EXTEND_HCI_ADV_NONCONN_IND;
		else if(adv_type == UHOS_BLE_ADV_TYPE_CONNECTABLE_DIRECTED_LDC)
			prop = EXTEND_HCI_ADV_LOW_DUTY_DIRECT_IND;

		adv_params_cp.properties = prop;
		adv_params_cp.max_interval[2] = 0x00;
		adv_params_cp.max_interval[1] = (htobs(max_interval) * 16 / 10) >> 8;
		adv_params_cp.max_interval[0] = (htobs(max_interval) * 16 / 10);
	
		adv_params_cp.min_interval[2] = 0x00;
		adv_params_cp.min_interval[1] = (htobs(min_interval) * 16 / 10) >> 8;
		adv_params_cp.min_interval[0] = (htobs(min_interval) * 16 / 10);
	
		adv_params_cp.chan_map = 0x07;
		adv_params_cp.tx_power = 0x7F;
		adv_params_cp.primary_phy = 0x01;
		adv_params_cp.secondary_phy = 0x01;

		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_EXTEND_ADVERTISING_PARAMETERS;
		rq.cparam = &adv_params_cp;
		rq.clen = LE_SET_EXTEND_ADVERTISING_PARAMETERS_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 2;
	}

	ret = hci_send_req(device_handle, &rq, 1000);
	if (ret < 0)
	{
		hci_close_dev(device_handle);
		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
		return;
	}

	hci_close_dev(device_handle);
}


static void hci_if_set_adv_disable()
{
	int device_id = hci_get_route(NULL);
	int ret = 0;
	int device_handle = 0;
	
	if((device_handle = hci_open_dev(device_id)) < 0)
	{
		LOGE("Could not open device");
		return;
	}

	uint8_t status;
	struct hci_request rq;
	memset(&rq, 0, sizeof(rq));

	if (hci_low_version) {
		le_set_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));
		advertise_cp.enable = 0x00;

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
		rq.cparam = &advertise_cp;
		rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	} else {
		le_set_extend_advertise_enable_cp advertise_cp;
		memset(&advertise_cp, 0, sizeof(advertise_cp));

		advertise_cp.enable = 0x00;
		advertise_cp.num_sets = 0x01;
		advertise_cp.handle = EXTEND_ADV_HANDLE;
		advertise_cp.duration = 0x00;
		advertise_cp.max_ext_adv_events = 0x00;

		memset(&rq, 0, sizeof(rq));
		rq.ogf = OGF_LE_CTL;
		rq.ocf = OCF_LE_SET_EXTEND_ADVERTISE_ENABLE;
		rq.cparam = &advertise_cp;
		rq.clen = LE_SET_EXTEND_ADVERTISE_ENABLE_CP_SIZE;
		rq.rparam = &status;
		rq.rlen = 1;
	}

	ret = hci_send_req(device_handle, &rq, 1000);

	if (ret < 0)
	{
		hci_close_dev(device_handle);
		LOGE("Can't send request %s (%d)\n", strerror(errno), errno);
		return;
	}

	hci_close_dev(device_handle);
}

static void hci_if_set_adv_data(uint8_t * adv_data, uint8_t adv_len,
									uint8_t * scan_rsp, uint8_t scan_rsp_len)
{
	// hci_if_set_scan_rsp(scan_rsp, scan_rsp_len);
	// hci_if_set_advertising_data(adv_data, adv_len);
}

static void hci_if_set_adv_start(uint8_t adv_type, uint16_t max_interval, uint16_t min_interval)
{
	hci_if_set_adv_param(adv_type, max_interval, min_interval);
	hci_if_set_scan_rsp(g_scan_rsp, g_scan_rsp_len);
	hci_if_set_adv_enable();
	hci_if_set_advertising_data(g_adv_data, g_adv_data_len);
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

	if (mgmt_low_version) {
		// hci_if_set_adv_data(g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
		return;
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
	g_adv_type = adv_type;
	g_min_interval = min_interval;
	g_max_interval = max_interval;
	if (mgmt_low_version) {
		hci_if_set_adv_start(adv_type, max_interval, min_interval);
		return;
	}

	advertising_set_adv_param(max_interval, min_interval);
	advertising_add_adv(adv_type, 0x01, g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
}

void bluez_gap_set_adv_stop()
{
	if (mgmt_low_version) {
		hci_if_set_adv_disable();
		return;
	}
	advertising_add_empty_adv(g_adv_type, 0x01);
	advertising_rm_adv(0x01);
}

void bluez_gap_set_adv_restart()
{
	if (mgmt_low_version) {
		hci_if_set_adv_disable();
		hci_if_set_adv_start(g_adv_type, g_max_interval, g_min_interval);
		return;
	}
	advertising_add_empty_adv(g_adv_type, 0x01);
	advertising_rm_adv(0x01);
	advertising_add_adv(g_adv_type, 0x01, g_adv_data, g_adv_data_len, g_scan_rsp, g_scan_rsp_len);
}

void bluez_gap_set_scan_start(uint8_t scan_type, uint16_t scan_interval, uint16_t scan_window,
								uint16_t timeout)
{
	set_scan_param(scan_interval, scan_window);
	start_scan();
}

void bluez_gap_set_scan_stop()
{
	stop_scan();
}

void bluez_gap_get_address(uint8_t addr[6])
{
	if (mgmt_index == MGMT_INDEX_NONE)
		return;
	memcpy(addr, public_addr, sizeof(public_addr));
}

void bluez_gap_disconnect(const bdaddr_t *bdaddr, uint8_t bdaddr_type)
{
	char addr[18], *name;
	struct mgmt_cp_disconnect *cp = malloc(sizeof(*cp));
	memset(cp, 0, sizeof(*cp));

	bacpy(&cp->addr.bdaddr, bdaddr);

	cp->addr.type = bdaddr_type;

	ba2str(bdaddr, addr);
	LOGW("type(%02x) bdaddr(%s)", bdaddr_type, addr);

	mgmt_send_wrapper(mgmt, MGMT_OP_DISCONNECT,
						mgmt_index, sizeof(*cp), cp,
						set_disconnect_rsp, NULL, NULL);
}

void bluez_gatts_send_notify_indicate(
	uint16_t conn_handle,
	uint16_t srv_handle,
	uint16_t char_value_handle,
	uint8_t offset,
	uint8_t *p_value,
	uint16_t len)
{
	gatts_send_async *msg = malloc(sizeof(gatts_send_async));

	msg->conn_handle = conn_handle;
	msg->srv_handle = srv_handle;
	msg->char_value_handle = char_value_handle;
	msg->offset = offset;
	msg->len = len;
	msg->p_value = malloc(len);
	memcpy(msg->p_value, p_value, len);

	if (!queue_push_tail(pending_gatts_list, msg)) {
		LOGE("add to pending_gatts_list failed");
		return;
	}

	int ret = eventfd_write(event_fd, 1);
	if (ret < 0) {
		LOGE("write event fd fail:%s", strerror(errno));
		return;
	}

	return;
}

void bluez_gap_get_conn_rssi(uint8_t *peer_addr, uint8_t type, uint8_t *rssi)
{
	struct mgmt_cp_get_conn_info *cp = malloc(sizeof(*cp));
	memset(cp, 0, sizeof(*cp));
	memcpy(cp->addr.bdaddr.b, peer_addr, 6);
	cp->addr.type = type;

	struct send_sync sync = {0x00};
	sync.opcode = MGMT_OP_GET_CONN_INFO;
	sync.userdata = malloc(256);
	sem_init(&sync.sem, 0, 0);

	if (mgmt_send_wrapper(mgmt, MGMT_OP_GET_CONN_INFO, mgmt_index, sizeof(*cp), cp,
					get_conn_info_rsp, &sync, NULL)) {
		LOGE("Send get_conn_info cmd fail");
		goto END;
	}

	sem_wait(&sync.sem);

	struct mgmt_rp_get_conn_info *rp = (struct mgmt_rp_get_conn_info *)sync.userdata;
	*rssi = rp->rssi;
END:
	sem_destroy(&sync.sem);
	free(sync.userdata);
	LOGI("get conn rssi = %d", *rssi);
}

void bluez_gap_set_static_address(uint8_t addr[6])
{
	memcpy(static_addr, addr, sizeof(static_addr));
	LOGD("Using static address %02x:%02x:%02x:%02x:%02x:%02x",
			static_addr[5], static_addr[4], static_addr[3],
			static_addr[2], static_addr[1], static_addr[0]);

	mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, mgmt_index,
						6, static_addr, NULL, NULL, NULL);
}

void bluez_gap_register_callback(bluez_gap_cmd_callback_func cmd_cb, bluez_gap_event_callback_func event_cb)
{
	g_cmd_cb = cmd_cb;
	g_event_cb = event_cb;
}

void bluez_gap_init(void)
{
	mgmt = mgmt_new_default();
	if (!mgmt) {
		LOGE("Failed to open management socket");
		return;
	}

	return ;
}

void bluez_gap_adapter_init(uint16_t hci_index)
{
	mgmt_index = hci_index;

	pending_cmd_list = queue_new();
	pending_cmd_tlv_list = queue_new();
	pending_gatts_list = queue_new();

	event_fd = eventfd(0, EFD_SEMAPHORE|EFD_NONBLOCK);
	// LOGW("event_fd = %d", event_fd);

	if (!mgmt_send(mgmt, MGMT_OP_READ_VERSION,
				MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, NULL, NULL)) {
		LOGE("Failed to read version");
		return;
	}
}

void bluez_gap_quit(void)
{
	LOGI("gap quit, revert br/edr settings.");

	if (!mgmt)
		return;

	{
		uint8_t * val = malloc(1);
		memset(val, 0x00, 1);

		LOGI("disable power settings.");
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_POWERED, mgmt_index, 1, val,
							power_complete, NULL, NULL);
	}

	{
		uint8_t * val = malloc(1);
		memset(val, 0x01, 1);

		LOGI("enable br/edr settings.");
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_BREDR, mgmt_index, 1, val,
							set_bredr_complete, NULL, NULL);
	}

	{
		uint8_t * val = malloc(1);
		memset(val, 0x00, 1);

		LOGI("disable le settings.");
		mgmt_send_wrapper(mgmt, MGMT_OP_SET_LE, mgmt_index, 1, val,
							set_le_complete, NULL, NULL);
	}
}

void bluez_gap_uinit(void)
{
	if (!mgmt)
		return;
	
	LOGI("gap uinit");
	
    mgmt_unref(mgmt);
	mgmt = NULL;

	mgmt_index = MGMT_INDEX_NONE;

	if (pending_cmd_list != NULL)
        queue_destroy(pending_cmd_list, free);

	if (pending_cmd_tlv_list != NULL)
        queue_destroy(pending_cmd_tlv_list, free);

	if (pending_gatts_list != NULL)
		queue_destroy(pending_gatts_list, free);

	memset(g_adv_data, 0x00, ADV_MAX_LENGTH);
	memset(g_scan_rsp, 0x00, ADV_MAX_LENGTH);
	g_adv_data_len = 0;
	g_scan_rsp_len = 0;
}
