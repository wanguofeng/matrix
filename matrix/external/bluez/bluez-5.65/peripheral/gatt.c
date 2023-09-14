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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <semaphore.h>

#include "lib/bluetooth.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-helpers.h"

#include "peripheral/gatt.h"
#include "peripheral/uh_ble.h"
#include "peripheral/conn_info.h" 
#include "peripheral/utils.h"

#define CONFIG_LOG_TAG "bluez_stack_gatt"
#include "peripheral/log.h"

#define ATT_CID 4

#define UUID_GAP 0x1800

struct gatt_conn {
	struct sockaddr_l2 addr;
	struct bt_att *att;
	struct bt_gatt_server *gatt;
// 	struct bt_gatt_client *client;
};

static int att_fd = -1;
static struct queue *conn_list = NULL;
static struct gatt_db *gatt_db = NULL;
// static struct gatt_db *gatt_cache = NULL;

static uint8_t static_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t dev_name[20];
static uint8_t dev_name_len = 0;

static bluez_gatts_event_callback_func g_gatts_cb;

static void gatts_callback(uhos_ble_gatts_evt_t evt, uhos_ble_gatts_evt_param_t *param, uint8_t addr[6], uint8_t addr_type)
{
    struct addr_info bdaddr;
    bdaddr.addr_type = addr_type;
    memcpy(bdaddr.addr, addr, 6);

    param->conn_handle = conn_info_get_handle_by_addr(bdaddr);
    LOGD("%s conn_handle = %04x", __FUNCTION__, param->conn_handle);

	if (g_gatts_cb != NULL)
		g_gatts_cb(evt, param);
}

void bluez_gatts_register_callback(bluez_gatts_event_callback_func func)
{
	g_gatts_cb = func;
}

void bluez_gatts_set_static_address(uint8_t addr[6])
{
	memcpy(static_addr, addr, 6);
}

void bluez_gatts_set_device_name(uint8_t name[20], uint8_t len)
{
	memcpy(dev_name, name, sizeof(dev_name));
	dev_name_len = len;
}

static void gatt_conn_destroy(void *data)
{
	struct gatt_conn *conn = data;

// 	bt_gatt_client_unref(conn->client);
	bt_gatt_server_unref(conn->gatt);
	bt_att_unref(conn->att);

	free(conn);
}

static void gatt_conn_disconnect(int err, void *user_data)
{
	struct gatt_conn *conn = user_data;

	printf("Device disconnected: %s\n", strerror(err));

	queue_remove(conn_list, conn);
	gatt_conn_destroy(conn);
}

static void client_ready_callback(bool success, uint8_t att_ecode,
							void *user_data)
{
	printf("GATT client discovery complete\n");
}

static void client_service_changed_callback(uint16_t start_handle,
						uint16_t end_handle,
						void *user_data)
{
	printf("GATT client service changed notification\n");
}

static struct gatt_conn *gatt_conn_new(int fd)
{
	struct gatt_conn *conn;
	uint16_t mtu = BT_ATT_MAX_LE_MTU;

	conn = new0(struct gatt_conn, 1);
	if (!conn)
		return NULL;

	conn->att = bt_att_new(fd, false);
	if (!conn->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		free(conn);
		return NULL;
	}

	bt_att_set_close_on_unref(conn->att, true);
	bt_att_register_disconnect(conn->att, gatt_conn_disconnect, conn, NULL);

	bt_att_set_security(conn->att, BT_SECURITY_LOW);

	conn->gatt = bt_gatt_server_new(gatt_db, conn->att, mtu, 0);
	if (!conn->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		bt_att_unref(conn->att);
		free(conn);
		return NULL;
	}

	// conn->client = bt_gatt_client_new(gatt_cache, conn->att, mtu, 0);
	// if (!conn->client) {
	// 	fprintf(stderr, "Failed to create GATT client\n");
	// 	bt_gatt_server_unref(conn->gatt);
	// 	bt_att_unref(conn->att);
	// 	free(conn);
	// 	return NULL;
	// }

	// bt_gatt_client_ready_register(conn->client, client_ready_callback,
	// 							conn, NULL);
	// bt_gatt_client_set_service_changed(conn->client,
	// 			client_service_changed_callback, conn, NULL);

	return conn;
}

static void att_conn_callback(int fd, uint32_t events, void *user_data)
{
	struct gatt_conn *conn;
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	int new_fd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	new_fd = accept(att_fd, (struct sockaddr *) &addr, &addrlen);
	if (new_fd < 0) {
		fprintf(stderr, "Failed to accept new ATT connection: %m\n");
		return;
	}

	LOGI("bdaddr(%02x:%02x:%02x:%02x:%02x:%02x) type(%02x)\n", addr.l2_bdaddr.b[5], addr.l2_bdaddr.b[4], addr.l2_bdaddr.b[3], 
			addr.l2_bdaddr.b[2], addr.l2_bdaddr.b[1], addr.l2_bdaddr.b[0], 
			addr.l2_bdaddr_type);


	conn = gatt_conn_new(new_fd);
	if (!conn) {
		fprintf(stderr, "Failed to create GATT connection\n");
		close(new_fd);
		return;
	}

	conn->addr = addr;
	memcpy(conn->addr.l2_bdaddr.b, addr.l2_bdaddr.b, 6);
	
	if (!queue_push_tail(conn_list, conn)) {
		fprintf(stderr, "Failed to add GATT connection\n");
		gatt_conn_destroy(conn);
		close(new_fd);
	}

	printf("New device connected\n");
}

static void gap_device_name_read(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t error;
	const uint8_t *value;
	size_t len;

	if (offset > dev_name_len) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		value = NULL;
		len = dev_name_len;
	} else {
		error = 0;
		len = dev_name_len - offset;
		value = len ? &dev_name[offset] : NULL;
	}

	gatt_db_attribute_read_result(attrib, id, error, value, len);
}

static void populate_gap_service(struct gatt_db *db)
{
	struct gatt_db_attribute *service, * device_name;
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, UUID_GAP);
	service = gatt_db_add_service(db, &uuid, true, 6);

	LOGD("gap service handle = %04x", gatt_db_attribute_get_handle(service));

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	device_name = gatt_db_service_add_characteristic(service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ,
					gap_device_name_read, NULL, NULL);

	LOGD("gap device_name handle = %04x", gatt_db_attribute_get_handle(device_name));

	gatt_db_service_set_active(service, true);
}

static void gatt_service_changed_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	LOGI("Service Changed Read called\n");

	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static uint8_t svc_chngd_enabled = false;
static uint16_t gatt_svc_chngd_handle = 0x00;

static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t value[2];

	LOGI("Service Changed CCC Read called\n");

	value[0] = svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	LOGI("Service Changed CCC Write called\n");

	if (!value || len != 2) {
		error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		svc_chngd_enabled = false;
	else if (value[0] == 0x02)
		svc_chngd_enabled = true;
	else
		error = 0x80;

	LOGI("Service Changed Enabled: %s\n",
				svc_chngd_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, error);
}

static void gatt_descriptor_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct server *server = user_data;
	uint8_t error = 0;

	LOGI("CCCD Write called\n");

	if (!value || len != 2) {
		error = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	// if (value[0] == 0x00)
	// 	svc_chngd_enabled = false;
	// else if (value[0] == 0x02)
	// 	svc_chngd_enabled = true;
	// else
	// 	error = 0x80;

	uint16_t handle = gatt_db_attribute_get_handle(attrib);
	LOGD("%s handle = %04x", __FUNCTION__, handle);

	uhos_ble_gatts_evt_t evt = UHOS_BLE_GATTS_EVT_CCCD_UPDATE;

	uhos_ble_gatts_evt_param_t *param = malloc(sizeof(uhos_ble_gatts_evt_param_t));
	param->write.value_handle = handle - 1;
	param->write.len = len;
	param->write.offset = offset;
	param->write.data = value;
	param->cccd = (uint32_t)*value;

	struct gatt_conn *conn = queue_peek_head(conn_list);

	gatts_callback(evt, param, conn->addr.l2_bdaddr.b, conn->addr.l2_bdaddr_type);

done:
	gatt_db_attribute_write_result(attrib, id, error);
	
	free(param);
}
// static void conf_cb(void *user_data)
// {
// 	LOGI("Received confirmation\n");
// }

// static void notify()
// {
// 	uint8_t value[4] = {0x01};

// 	struct gatt_conn *conn = queue_peek_head(conn_list);

// 	if (!bt_gatt_server_send_indication(conn->gatt, gatt_svc_chngd_handle,
// 					value, sizeof(value),
// 					conf_cb, NULL, NULL))
// 		LOGI("Failed to initiate indication\n");
// }

static void populate_gatt_service(struct gatt_db *db)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *svc_chngd, *cccd;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, 0x1801);
	service = gatt_db_add_service(db, &uuid, true, 4);

	LOGD("gatt service handle = %04x", gatt_db_attribute_get_handle(service));

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, NULL);

	gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	LOGD("gatt_svc_chngd_handle = %04x", gatt_svc_chngd_handle);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	cccd = gatt_db_service_add_descriptor(service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, NULL);

	LOGD("cccd handle = %04x", gatt_db_attribute_get_handle(cccd));

	gatt_db_service_set_active(service, true);
}

static void gatt_character_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	LOGI("Character Read called\n");

	uint16_t handle = gatt_db_attribute_get_handle(attrib);
	LOGD("%s handle = %04x", __FUNCTION__, handle);

	uhos_ble_gatts_evt_t evt = UHOS_BLE_GATTS_EVT_READ;
	uhos_ble_gatts_evt_param_t *param = malloc(sizeof(uhos_ble_gatts_evt_param_t));

	uint8_t *value = NULL;
	uint16_t len = 5;

	param->read.value_handle = handle;
	param->read.offset = offset;
	param->read.data = &value;
	param->read.len = &len;

	struct gatt_conn *conn = queue_peek_head(conn_list);

	gatts_callback(evt, param, conn->addr.l2_bdaddr.b, conn->addr.l2_bdaddr_type);

	LOGI("gatt read len = %d", len);

	LOG_HEXDUMP_DBG(value, len, "gatt read");

	gatt_db_attribute_read_result(attrib, id, 0, value, len);

	// if (value != NULL)
	// 	free(value);

	free(param);
}

static void gatt_character_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t ecode = 0;

	if (!value) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	uint16_t handle = gatt_db_attribute_get_handle(attrib);
	LOGD("%s handle = %04x", __FUNCTION__, handle);

	uhos_ble_gatts_evt_t evt = UHOS_BLE_GATTS_EVT_WRITE;

	uhos_ble_gatts_evt_param_t *param = malloc(sizeof(uhos_ble_gatts_evt_param_t));
	param->write.value_handle = handle;
	param->write.len = len;
	param->write.offset = offset;
	param->write.data = value;

	struct gatt_conn *conn = queue_peek_head(conn_list);

	LOG_HEXDUMP_DBG(value, len, "gatt write");

	gatts_callback(evt, param, conn->addr.l2_bdaddr.b, conn->addr.l2_bdaddr_type);

done:
	gatt_db_attribute_write_result(attrib, id, ecode);

	free(param);
}

void bluez_gatts_send_notification(uint16_t char_handle, const uint8_t *value, uint16_t length)
{
	struct gatt_conn *conn = queue_peek_head(conn_list);

	LOGI("%s handle = %04x, length = %d", __FUNCTION__, char_handle, length);
	
	LOG_HEXDUMP_DBG(value, length, "notification");

	bt_gatt_server_send_notification(conn->gatt,
					char_handle, value,
					length, false);
}

void bluez_gatts_send_indication(uint16_t char_handle, const uint8_t *value, uint16_t length)
{
	struct gatt_conn *conn = queue_peek_head(conn_list);

	LOGI("%s handle = %04x, length = %d", __FUNCTION__, char_handle, length);

	LOG_HEXDUMP_DBG(value, length, "indication");

	bt_gatt_server_send_indication(conn->gatt,
					char_handle, value,
					length,
					NULL, NULL, NULL);
}

void bluez_gatts_set_mtu(uint16_t mtu)
{
	struct gatt_conn *conn = queue_peek_head(conn_list);
	if (conn != NULL)
		bt_gatt_exchange_mtu(conn->att, mtu, NULL, NULL, NULL);
}

void bluez_gatts_get_mtu(uint16_t *mtu)
{
	struct gatt_conn *conn = queue_peek_head(conn_list);
	if (conn != NULL)
		*mtu = bt_gatt_server_get_mtu(conn->gatt);
}

void bluez_gatts_add_service(uhos_ble_gatts_srv_db_t *p_srv_db)
{
	if (gatt_db == NULL) {
		LOGE("gatt_db is null");
		return;
	}

	if (p_srv_db == NULL) {
		LOGE("p_srv_db is null");
		return;
	}

	if (p_srv_db->char_num == 0) {
		LOGE("p_srv_db->char_num is zero");
		return;
	}

	bt_uuid_t uuid;
	struct gatt_db_attribute *service, *character, *cccd;

	if (p_srv_db->srv_uuid.type == UHOS_BLE_UUID_TYPE_16) {
		bt_uuid16_create(&uuid, p_srv_db->srv_uuid.uuid16);
	} else {
		uint128_t u128;
		bswap_128(p_srv_db->srv_uuid.uuid128, &u128);
		bt_uuid128_create(&uuid, u128);
	}

	if (p_srv_db->srv_type == UHOS_BLE_PRIMARY_SERVICE) {
		service = gatt_db_add_service(gatt_db, &uuid, true, p_srv_db->char_num * 4);
	} else {
		service = gatt_db_add_service(gatt_db, &uuid, false, p_srv_db->char_num * 4);
	}

	p_srv_db->srv_handle = gatt_db_attribute_get_handle(service);

	LOGI("gatt service handle = %04x", p_srv_db->srv_handle);

	for (int i = 0; i < p_srv_db->char_num; i ++) {

		uhos_ble_gatts_char_db_t *char_db = &p_srv_db->p_char_db[i];

		if (char_db->char_uuid.type == UHOS_BLE_UUID_TYPE_16) {
			bt_uuid16_create(&uuid, char_db->char_uuid.uuid16);
		} else {
			uint128_t u128;
			bswap_128(char_db->char_uuid.uuid128, &u128);
			bt_uuid128_create(&uuid, u128);
		}

		uint32_t permission = 0;
		uint8_t properties = 0;
		gatt_db_read_t read_callback = NULL;
		gatt_db_write_t write_callback = NULL;
		bool is_cccd_exit = false;

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_BROADCAST)
			properties |= BT_GATT_CHRC_PROP_BROADCAST;

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_READ) {
			properties |= BT_GATT_CHRC_PROP_READ;
			permission |= BT_ATT_PERM_READ;
			read_callback = gatt_character_read_cb;
		}

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_WRITE_WITHOUT_RESP) {
			properties |= BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP;
			permission |= BT_ATT_PERM_WRITE;
			write_callback = gatt_character_write_cb;
		}

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_WRITE) {
			properties |= BT_GATT_CHRC_PROP_WRITE;
			permission |= BT_ATT_PERM_WRITE;
			write_callback = gatt_character_write_cb;
		}

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_NOTIFY) {
			properties |= BT_GATT_CHRC_PROP_NOTIFY;
			is_cccd_exit = true;
		}

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_INDICATE) {
			properties |= BT_GATT_CHRC_PROP_INDICATE;
			is_cccd_exit = true;
		}

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_AUTH_SIGNED_WRITE)
			properties |= BT_GATT_CHRC_PROP_AUTH;

		if (char_db->char_property & UHOS_BLE_CHAR_PROP_EXTENDED_PROPERTIES)
			properties |= BT_GATT_CHRC_PROP_EXT_PROP;

		character = gatt_db_service_add_characteristic(service, &uuid,
					permission,
					properties,
					read_callback,
					write_callback, NULL);

		char_db->char_value_handle = gatt_db_attribute_get_handle(character);

		LOGI("char_value_handle = %04x", char_db->char_value_handle);

		if (is_cccd_exit) {
			bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
			cccd = gatt_db_service_add_descriptor(service, &uuid,
								BT_ATT_PERM_WRITE,
								NULL,
								gatt_descriptor_ccc_write_cb, NULL);

			LOGI("cccd handle = %04x", gatt_db_attribute_get_handle(cccd));
		}
		gatt_db_service_set_active(service, true);
	}
}

void bluez_gatts_server_start(void)
{
	struct sockaddr_l2 addr;

	if (att_fd >= 0)
		return;

	att_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC,
							BTPROTO_L2CAP);
	if (att_fd < 0) {
		fprintf(stderr, "Failed to create ATT server socket: %m\n");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	addr.l2_cid = htobs(ATT_CID);
	// memset(static_addr, 0x00, 6);
	memcpy(&addr.l2_bdaddr, static_addr, 6);

	addr.l2_bdaddr_type = BDADDR_LE_RANDOM;

	LOGI("bind addr %02x:%02x:%02x:%02x:%02x:%02x\n", static_addr[5], static_addr[4], static_addr[3],
					static_addr[2], static_addr[1], static_addr[0]);
	
	if (bind(att_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to bind ATT server socket: %m\n");
		close(att_fd);
		att_fd = -1;
		return;
	}

	struct bt_security btsec;
	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = BT_SECURITY_LOW;
	if (setsockopt(att_fd, SOL_BLUETOOTH, BT_SECURITY, &btsec,
							sizeof(btsec)) != 0) {
		LOGE("Failed to set L2CAP security level");
		return;
	}

	if (listen(att_fd, 1) < 0) {
		fprintf(stderr, "Failed to listen on ATT server socket: %m\n");
		close(att_fd);
		att_fd = -1;
		return;
	}

	gatt_db = gatt_db_new();
	if (!gatt_db) {
		close(att_fd);
		att_fd = -1;
		return;
	}

	// gatt_cache = gatt_db_new();

	conn_list = queue_new();
	if (!conn_list) {
		LOGE("create conn_list failed");
		gatt_db_unref(gatt_db);
		gatt_db = NULL;
		return;
	}

#if 1
	if (gatt_db != NULL) {
		// populate_devinfo_service(gatt_db);
		populate_gap_service(gatt_db);
		populate_gatt_service(gatt_db);
		// populate_app_service(gatt_db);
	}
#endif

	mainloop_add_fd(att_fd, EPOLLIN, att_conn_callback, NULL, NULL);
}

void bluez_gatts_server_stop(void)
{
	if (att_fd < 0)
		return;

	mainloop_remove_fd(att_fd);

	queue_destroy(conn_list, gatt_conn_destroy);

	// gatt_db_unref(gatt_cache);
	// gatt_cache = NULL;

	gatt_db_unref(gatt_db);
	gatt_db = NULL;

	close(att_fd);
	att_fd = -1;
}