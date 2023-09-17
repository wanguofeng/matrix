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
#include <pthread.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"

#include "lib/mgmt.h"
#include "src/shared/mgmt.h"
#include "adapter/gatt.h"
#include "adapter/gap.h"
#include "adapter/utils.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#define CONFIG_LOG_TAG "bluez_stack_gap_mgmt"
#include "adapter/log.h"

#include "adapter/utils.h"
#include "adapter/conn_info.h"

#define ADV_MAX_LENGTH	31

static int event_fd = 0;

static struct queue *pending_cmd_list = NULL;
static struct queue *pending_cmd_tlv_list = NULL;

static struct mgmt *mgmt = NULL;
static uint16_t mgmt_index = MGMT_INDEX_NONE;
static uint8_t mgmt_version = 0;
static uint8_t mgmt_revision = 0;

static bool adv_features = false;
static bool adv_instances = false;
static bool require_connectable = true;
static unsigned int discovery_id = -1;

static uint8_t static_addr[6] = { 0x90, 0x78, 0x56, 0x34, 0x12, 0xc0 };
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

static bluez_gap_callback_func gap_cb = NULL;
static bluez_init_callback_func init_cb = NULL;

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

static int8_t mgmt_send_wrapper(struct mgmt *mgmt, uint16_t opcode, uint16_t index,
				uint16_t length, void *param,
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

	if (!queue_push_head(pending_cmd_list, mgmt_cmd)) {
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

	if (!queue_push_head(pending_cmd_tlv_list, mgmt_send_tlv)) {
		LOGE("add to pending_cmd_tlv_list failed");
	}
	int ret = eventfd_write(event_fd, 1);
	if (ret < 0) {
		LOGE("write event fd fail:%s", strerror(errno));
		return -1;
	}

	return 0;
}

static void gap_event_callback(uint16_t event, uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
    switch(event)
    {
        case MGMT_EV_DEVICE_CONNECTED:
        {
            const struct mgmt_ev_device_connected *ev = param;
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            
            struct addr_info bdaddr;

            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            uint8_t role = conn_info_get_role_by_addr(bdaddr);
            evt_param.conn_handle = conn_info_generate_handle();
            evt_param.connect.role = role;

            LOGI("connected handle = %04x", evt_param.conn_handle);

            if (ev->addr.type == BDADDR_LE_PUBLIC) {
                evt_param.connect.type = UHOS_BLE_ADDRESS_TYPE_PUBLIC;
            } else if (ev->addr.type == BDADDR_LE_RANDOM) {
                evt_param.connect.type = UHOS_BLE_ADDRESS_TYPE_RANDOM;
            } else {
                evt_param.connect.type = 0x02; // unknow;
            }

            memcpy(evt_param.connect.peer_addr, ev->addr.bdaddr.b, 6);

            evt_param.connect.conn_param.conn_sup_timeout = 0x00; // can't get this param;
            evt_param.connect.conn_param.max_conn_interval = 0x00; // can't get this param;
            evt_param.connect.conn_param.min_conn_interval = 0x00; // can't get this param;
            evt_param.connect.conn_param.slave_latency = 0x00; // can't get this param;

            conn_info_add_gatts(evt_param.conn_handle, bdaddr);

			if (gap_cb != NULL)
            	gap_cb(UHOS_BLE_GAP_EVT_CONNECTED, &evt_param);

            break;
        }   
        case MGMT_EV_DEVICE_DISCONNECTED:
        {
            const struct mgmt_ev_device_disconnected *ev = param;

            uhos_ble_gap_evt_param_t evt_param = {0x00};

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);

            uint8_t reason = UNKNOW_OTHER_ERROR;

            if (ev->reason == MGMT_DEV_DISCONN_REMOTE) {
                reason = UHOS_BLE_REMOTE_USER_TERMINATED;
            } else if (ev->reason == MGMT_DEV_DISCONN_TIMEOUT) {
                reason = UHOS_BLE_CONNECTION_TIMEOUT;
            } else if (ev->reason == MGMT_DEV_DISCONN_LOCAL_HOST) {
                reason = UHOS_BLE_LOCAL_HOST_TERMINATED;
            } else {
                reason = UNKNOW_OTHER_ERROR;
            }

            LOGE("disconnect handle = %04x", evt_param.conn_handle);

            evt_param.disconnect.reason = reason;
            conn_info_del_gatts(evt_param.conn_handle, bdaddr);
			
			if (gap_cb != NULL)
           		gap_cb(UHOS_BLE_GAP_EVT_DISCONNET, &evt_param);
            
			break;
        }
        case MGMT_EV_NEW_CONN_PARAM:
        {
            const struct mgmt_ev_new_conn_param * ev = param;
            uhos_ble_gap_evt_param_t evt_param = {0x00};

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, ev->addr.bdaddr.b, 6);
            bdaddr.addr_type = ev->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);
            evt_param.update_conn.conn_param.conn_sup_timeout = ev->timeout;
            evt_param.update_conn.conn_param.max_conn_interval = ev->max_interval;
            evt_param.update_conn.conn_param.min_conn_interval = ev->min_interval;
            evt_param.update_conn.conn_param.slave_latency = ev->latency;
			
			if (gap_cb != NULL)
           		gap_cb(UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED, &evt_param);

            break;
        }
        case MGMT_EV_DEVICE_FOUND:
        {
            const struct mgmt_ev_device_found * ev = param;
            uint16_t eir_len;
            uint32_t flags;
            if (length < sizeof(*ev)) {
                LOGE("Too short device_found length (%u bytes)", length);
                return;
            }
            LOGI("adv data len(%d)", ev->eir_len);
            if (ev->eir_len > 31) {
                LOGI("len(%d) can't process yet", ev->eir_len);
                return;
            }
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            evt_param.conn_handle = 0x00; // not used
            evt_param.report.addr_type = ev->addr.type;
            evt_param.report.adv_type = FULL_DATA; // can't get adv type(refers PDU Type)
            evt_param.report.data_len = ev->eir_len;
            memcpy(evt_param.report.peer_addr, ev->addr.bdaddr.b, 6);
            evt_param.report.rssi = ev->rssi;;
            memcpy(evt_param.report.data, ev->eir, ev->eir_len);

			if (gap_cb != NULL)
            	gap_cb(UHOS_BLE_GAP_EVT_ADV_REPORT, &evt_param);

            break;
        }
    }
}

static void gap_cmd_callback(uint16_t cmd, int8_t status, uint16_t len,
					const void *param, void *user_data)
{
    switch(cmd)
    {
        case MGMT_OP_DISCONNECT:
        {
            uhos_ble_gap_evt_param_t evt_param = {0x00};
            const struct mgmt_rp_disconnect *rp = param;

            struct addr_info bdaddr;
            memcpy(bdaddr.addr, rp->addr.bdaddr.b, 6);
            bdaddr.addr_type = rp->addr.type;

            evt_param.conn_handle = conn_info_get_handle_by_addr(bdaddr);
            uint8_t reason = MGMT_DEV_DISCONN_LOCAL_HOST;
            evt_param.disconnect.reason = reason;
            conn_info_del_gatts(evt_param.conn_handle, bdaddr);
			
			if (gap_cb != NULL)
            	gap_cb(UHOS_BLE_GAP_EVT_DISCONNET, &evt_param);

            break;
        }
        default:
            break;
    }
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
	gap_event_callback(MGMT_EV_DEVICE_CONNECTED, index, length, param, user_data);
}

static void device_disconnected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	LOGD("Device disconnected");
	gap_event_callback(MGMT_EV_DEVICE_DISCONNECTED, index, length, param, user_data);
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
	gap_event_callback(MGMT_EV_NEW_CONN_PARAM, index, length, param, user_data);
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
		init_cb(status);
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
	
	gap_cmd_callback(MGMT_OP_READ_DEF_SYSTEM_CONFIG, status, len, param, user_data);

	init_cb(status);
}

static void reset_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	LOGD("reset complete");
	
	gap_cmd_callback(MGMT_OP_SET_POWERED, status, len, param, user_data);

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

	gap_cmd_callback(MGMT_OP_READ_ADV_FEATURES, status, len, param, user_data);

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

	gap_cmd_callback(MGMT_OP_READ_INFO, status, len, param, user_data);

	if (status) {
		LOGE("Reading info for index %u failed: %s",
						index, mgmt_errstr(status));
		return;
	}

	supported_settings = le32_to_cpu(rp->supported_settings);
	current_settings = le32_to_cpu(rp->current_settings);

	if ((supported_settings & required_settings) != required_settings) {
		LOGI("Index %d doesn't support BLE Features ", index);
		return;
	}

	if ((mgmt_index != MGMT_INDEX_NONE) && (mgmt_index != index)) {
		LOGI("Selecting index %u already", mgmt_index);
		return;
	}

	LOGI("Selecting index %u", index);

	mgmt_index = index;

	memcpy(public_addr, (uint8_t *)&rp->bdaddr, 6);

	static_addr[0] = rand(); 
	static_addr[1] = rand();
	static_addr[2] = rand();
	static_addr[3] = rand();
	static_addr[4] = rand();
	static_addr[5] = 0xc0;

	LOGD("Generate static addr %02x:%02x:%02x:%02x:%02x:%02x\n", static_addr[5], static_addr[4], static_addr[3],
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

	mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index,
	 				6, static_addr, NULL, NULL, NULL);

	bluez_gatts_set_static_address(static_addr);
	bluez_gatts_set_device_name(dev_name, dev_name_len);
	bluez_gatts_server_start();

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

	gap_cmd_callback(MGMT_OP_READ_INDEX_LIST, status, len, param, user_data);

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

	gap_cmd_callback(MGMT_OP_READ_COMMANDS, status, len, param, user_data);

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

	gap_cmd_callback(MGMT_OP_READ_VERSION, status, len, param, user_data);

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

	gap_cmd_callback(MGMT_OP_DISCONNECT, status, len, param, user_data);
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

	gap_event_callback(MGMT_EV_DEVICE_FOUND, index, len, param, user_data);
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
	g_adv_type = adv_type;
	g_min_interval = min_interval;
	g_max_interval = max_interval;

	advertising_set_adv_param(max_interval, min_interval);
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

void bluez_gap_disconnect(uint16_t conn_handle)
{
    struct addr_info info = {0x00};
    conn_info_get_addr_by_handle(conn_handle, &info);

    LOGI("disconnect conn_handle(%04x)", conn_handle);

    bdaddr_t bdaddr = {0x00};
    memcpy(bdaddr.b, info.addr, 6);

	char addr[18] = {0x00};
	struct mgmt_cp_disconnect *cp = malloc(sizeof(*cp));
	memset(cp, 0, sizeof(*cp));

	bacpy(&cp->addr.bdaddr, &bdaddr);
	cp->addr.type = info.addr_type;

	ba2str(&bdaddr, addr);
	LOGI("type(%02x) bdaddr(%s)", info.addr_type, addr);

	mgmt_send_wrapper(mgmt, MGMT_OP_DISCONNECT,
						mgmt_index, sizeof(*cp), cp,
						set_disconnect_rsp, NULL, NULL);
}

void bluez_gap_get_conn_rssi(uint16_t conn_handle, uint8_t *rssi)
{
    struct addr_info bdaddr = {0x00};
    conn_info_get_addr_by_handle(conn_handle, &bdaddr);

	struct mgmt_cp_get_conn_info *cp = malloc(sizeof(*cp));
	memset(cp, 0, sizeof(*cp));
	memcpy(&cp->addr.bdaddr, bdaddr.addr, 6);
	cp->addr.type = bdaddr.addr_type;

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
}

void bluez_gap_set_static_address(uint8_t addr[6])
{
	memcpy(static_addr, addr, sizeof(static_addr));
	LOGD("Using static address %02x:%02x:%02x:%02x:%02x:%02x",
			static_addr[5], static_addr[4], static_addr[3],
			static_addr[2], static_addr[1], static_addr[0]);

	mgmt_send_wrapper(mgmt, MGMT_OP_SET_STATIC_ADDRESS, mgmt_index,
						6, static_addr, NULL, NULL, NULL);
}

void bluez_gap_register_callback(bluez_gap_callback_func func)
{
	gap_cb = func;
}

int bluez_gap_init(bluez_init_callback_func func)
{
	mgmt = mgmt_new_default();
	if (!mgmt) {
		LOGE("Failed to open management socket");
		func(-1);
		return -1;
	}

	pending_cmd_list = queue_new();
	pending_cmd_tlv_list = queue_new();

	event_fd = eventfd(0, EFD_SEMAPHORE|EFD_NONBLOCK);	
	mainloop_add_fd(event_fd, EPOLLIN, recv_cmd, NULL, NULL);

    conn_info_init();

	if (!mgmt_send(mgmt, MGMT_OP_READ_VERSION,
				MGMT_INDEX_NONE, 0, NULL,
				read_version_complete, NULL, NULL)) {
		LOGE("Failed to read version");
		func(-1);
		return -1;
	}

	init_cb = func;
	return 0;
}

void bluez_gap_uinit(void)
{
	if (!mgmt)
		return;

    mgmt_unref(mgmt);
	mgmt = NULL;

	mgmt_index = MGMT_INDEX_NONE;

	if (pending_cmd_list != NULL)
        queue_destroy(pending_cmd_list, free);

	if (pending_cmd_tlv_list != NULL)
        queue_destroy(pending_cmd_tlv_list, free);

	conn_info_deinit();
}
