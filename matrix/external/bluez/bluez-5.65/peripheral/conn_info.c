#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "peripheral/conn_info.h"

#define CONFIG_LOG_TAG "Bluez_Stack/ConnInfo"
#include "peripheral/log.h"

#define INVAILD_CONNECTION_HANDLE				0x0000
#define MIN_CONNECTION_HANDLE					0x0001
#define MAX_CONNECTION_HANDLE					0x7FFF

#define BASE_GATTS_CONNECTION_HANDLE			0x0000
#define BASE_GATTC_CONNECTION_HANDLE			0x8000					

#define BLE_GAP_BROADCASTER						0x00
#define BLE_GAP_OBSERVER						0x01
#define BLE_GAP_PERIPHERAL						0x02
#define BLE_GAP_CENTRAL							0x03

static struct queue *gattc_conn_list = NULL;
static struct queue *gatts_conn_list = NULL;

static bool match_by_addr(const void *data, const void *user_data)
{
	const struct conn_info * d = data;
	const struct conn_info * u = user_data;
	
	return (memcmp(d->bdaddr.addr, u->bdaddr.addr, 6) == 0);
}

static bool match_by_conn_handle(const void *data, const void *user_data)
{
	const struct conn_info * d = data;
	const struct conn_info * u = user_data;
	
	if (d->conn_handle == u->conn_handle)
		return true;
	else
		return false;
}

uint16_t conn_info_generate_handle(uint8_t role)
{
	static uint16_t conn_handle = MIN_CONNECTION_HANDLE;
	uint16_t handle = conn_handle ++;

	if (MAX_CONNECTION_HANDLE == handle)
		conn_handle = MIN_CONNECTION_HANDLE;
	
	if (role == BLE_GAP_PERIPHERAL)
		return handle + BASE_GATTS_CONNECTION_HANDLE;
	else 
		return handle + BASE_GATTC_CONNECTION_HANDLE;
}

void conn_info_init()
{
    gattc_conn_list = queue_new();
    gatts_conn_list = queue_new();
}

void conn_info_deinit()
{
    if (gattc_conn_list != NULL)
        queue_destroy(gattc_conn_list, free);

    if (gatts_conn_list != NULL)
        queue_destroy(gatts_conn_list, free);
}

void conn_info_add_gatts(uint16_t conn_handle, const struct addr_info bdaddr)
{
	struct conn_info * cp = malloc(sizeof(struct conn_info));

	cp->conn_handle = conn_handle;
	cp->bdaddr.addr_type = bdaddr.addr_type;
	memcpy(cp->bdaddr.addr, bdaddr.addr, 6);

	if (!queue_push_tail(gatts_conn_list, cp)) {
		LOGE("add to gatts_conn_list failed");
	}
}

void conn_info_del_gatts(uint16_t conn_handle, const struct addr_info bdaddr)
{
	struct conn_info temp;
	temp.conn_handle = conn_handle;
	temp.bdaddr.addr_type = bdaddr.addr_type;
	memcpy(temp.bdaddr.addr, bdaddr.addr, 6);

	struct conn_info * cp = queue_find(gatts_conn_list, match_by_addr,
							&temp);
	if (cp != NULL) {
 		queue_remove(gatts_conn_list, cp);
		free(cp);
		return;
	}

	cp = queue_find(gatts_conn_list, match_by_conn_handle,
							&temp);
	if (cp != NULL) {
 		queue_remove(gatts_conn_list, cp);
		free(cp);
		return;
	}
}

void conn_info_add_gattc(uint16_t conn_handle, const struct addr_info bdaddr)
{
	struct conn_info * cp = malloc(sizeof(struct conn_info));

	cp->conn_handle = conn_handle;
	cp->bdaddr.addr_type = bdaddr.addr_type;
	memcpy(cp->bdaddr.addr, bdaddr.addr, 6);

	if (!queue_push_tail(gatts_conn_list, cp)) {
		LOGE("add to gatts_conn_list failed");
	}
}

void conn_info_del_gattc(uint16_t conn_handle, const struct addr_info bdaddr)
{
	struct conn_info temp;
	temp.conn_handle = conn_handle;
	temp.bdaddr.addr_type = bdaddr.addr_type;
	memcpy(temp.bdaddr.addr, bdaddr.addr, 6);

	struct conn_info * cp = queue_find(gattc_conn_list, match_by_addr,
							&temp);
	if (cp != NULL) {
 		queue_remove(gattc_conn_list, cp);
		free(cp);
		return;
	}

	cp = queue_find(gattc_conn_list, match_by_conn_handle,
							&temp);
	if (cp != NULL) {
 		queue_remove(gattc_conn_list, cp);
		free(cp);
		return;
	}
}

uint8_t conn_info_get_role_by_addr(const struct addr_info bdaddr)
{
	struct conn_info temp;
	memcpy(temp.bdaddr.addr, bdaddr.addr, 6);
	temp.bdaddr.addr_type = bdaddr.addr_type;

	struct conn_info * cp = queue_find(gattc_conn_list, match_by_addr,
							&temp);
	if (cp != NULL) {
		return BLE_GAP_CENTRAL;
	}

	return BLE_GAP_PERIPHERAL;
}

uint8_t conn_info_get_role_by_handle(uint16_t conn_handle)
{
	struct conn_info temp;
	temp.conn_handle = conn_handle;

	struct conn_info * cp = queue_find(gattc_conn_list, match_by_conn_handle,
							&temp);
	if (cp != NULL) {
		return BLE_GAP_CENTRAL;
	}

	return BLE_GAP_PERIPHERAL;
}

uint8_t conn_info_get_addr_by_handle(uint16_t conn_handle, struct addr_info * bdaddr)
{
	struct conn_info temp;
	temp.conn_handle = conn_handle;

	if (conn_handle < BASE_GATTC_CONNECTION_HANDLE) {
		struct conn_info * cp = queue_find(gatts_conn_list, match_by_conn_handle,
											&temp);
		if (cp == NULL) {
			return -1;
		}
		memcpy(bdaddr->addr, cp->bdaddr.addr, 6);
		bdaddr->addr_type = cp->bdaddr.addr_type;
	} else {
		struct conn_info * cp = queue_find(gattc_conn_list, match_by_conn_handle,
											&temp);
		if (cp == NULL) {
			return -1;
		}
		memcpy(bdaddr->addr, cp->bdaddr.addr, 6);
		bdaddr->addr_type = cp->bdaddr.addr_type;
	}
	return 0;
}

uint8_t conn_info_get_handle_by_addr(const struct addr_info bdaddr)
{
	struct conn_info temp;
	memcpy(temp.bdaddr.addr, bdaddr.addr, 6);
	temp.bdaddr.addr_type = bdaddr.addr_type;

	struct conn_info * cp = queue_find(gatts_conn_list, match_by_addr,
							&temp);
	if (cp != NULL) {
		return cp->conn_handle;
	}

	cp = queue_find(gattc_conn_list, match_by_addr,
							&temp);
	if (cp != NULL) {
		return cp->conn_handle;
	}

	return INVAILD_CONNECTION_HANDLE;
}