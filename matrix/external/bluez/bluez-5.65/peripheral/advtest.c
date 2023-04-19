// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>
#include <pthread.h>

#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"
#include "src/shared/hci.h"
#include "src/shared/crypto.h"

#include "peripheral/adv.h"
#include "peripheral/gatt.h"

#define PEER_ADDR_TYPE	0x00
#define PEER_ADDR	"\x00\x00\x00\x00\x00\x00"

static struct bt_hci *adv_dev;
static struct bt_hci *scan_dev;

static uint8_t device_addr[6] = {0x00};

static bluez_gap_event_callback_func g_event_callback = NULL;

static void event_cb(uint16_t event, const void *data, uint8_t size, void *user_data)
{
	if (g_event_callback != NULL) {
		g_event_callback(event, data, size, user_data);
	}
} 

static void disconnect_event(const void *data, uint8_t size,
							void *user_data)
{
	event_cb(BT_HCI_EVT_DISCONNECT_COMPLETE, data, size, user_data);
}

static void scan_le_meta_event(const void *data, uint8_t size,
							void *user_data)
{
	event_cb(BT_HCI_EVT_LE_META_EVENT, data, size, user_data);
}

static void scan_enable_callback(const void *data, uint8_t size,
							void *user_data)
{

}

static void adv_le_features_callback(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_le_read_local_features *rsp = data;

	if (rsp->status) {
		fprintf(stderr, "Failed to read local LE features\n");
		mainloop_exit_failure();
		return;
	}
}

static void le_set_event_mask_callback(const void *data, uint8_t size,
							void *user_data)
{
	printf("set le event mask done\n");
}

static void read_bd_addr_callback(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_bd_addr *rsp = data;
	if (rsp->status) {
		fprintf(stderr, "Failed to read local LE features\n");
		mainloop_exit_failure();
		return;
	}
	printf("read bd addr %02x:%02x:%02x:%02x:%02x:%02x\n", rsp->bdaddr[0], rsp->bdaddr[1], rsp->bdaddr[2],
														 rsp->bdaddr[3], rsp->bdaddr[4], rsp->bdaddr[5]);
	memcpy(device_addr, rsp->bdaddr, 6);

	gatt_set_static_address(device_addr);
	gatt_set_device_name("wanguofeng", sizeof("wanguofeng"));
}

static void local_features_callback(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_local_features *rsp = data;

	if (rsp->status) {
		fprintf(stderr, "Failed to read local features\n");
		mainloop_exit_failure();
		return;
	}

	if (!(rsp->features[4] & 0x40)) {
		fprintf(stderr, "Controller without Low Energy support\n");
		mainloop_exit_failure();
		return;
	}
}

uint16_t hci_index = 0xFFFF;

static void hciconfig_hcix_down()
{
	int ctl = 0;

	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		return;
	}

	/* Stop HCI device */
	if (ioctl(ctl, HCIDEVDOWN, hci_index) < 0) {
		close(ctl);
		fprintf(stderr, "Can't down device hci%d: %s (%d)\n",
						hci_index, strerror(errno), errno);
		return;
	}

	close(ctl);
}

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

void bluez_register_gap_event_callback(bluez_gap_event_callback_func func)
{
	g_event_callback = func;
}

void bluez_set_gap_disconnect(uint16_t conn_handle)
{
	struct bt_hci_cmd_disconnect cmd;

	cmd.handle = conn_handle;
	cmd.reason = 0x13;

	bt_hci_send(adv_dev, BT_HCI_CMD_DISCONNECT,
					&cmd, sizeof(cmd), NULL, NULL, NULL);
}

void bluez_set_gap_connect(uint16_t scan_interval, uint16_t scan_window,
					uint8_t peer_addr_type, uint8_t peer_addr[6], uint8_t own_addr_type,
					uint16_t min_interval, uint16_t max_interval, uint16_t latency, uint16_t supv_timeout)
{
	struct bt_hci_cmd_le_create_conn cmd;

	memset(&cmd, 0, sizeof(cmd));
	memcpy(cmd.peer_addr, peer_addr, sizeof(cmd.peer_addr));

	cmd.peer_addr_type = peer_addr_type;
	cmd.scan_interval = cpu_to_le16(scan_interval);
	cmd.scan_window = cpu_to_le16(scan_window);
	cmd.own_addr_type = own_addr_type;
	cmd.min_interval = cpu_to_le16(min_interval);
	cmd.max_interval = cpu_to_le16(max_interval);
	cmd.latency = cpu_to_le16(latency);
	cmd.supv_timeout = cpu_to_le16(supv_timeout);

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_CREATE_CONN,
						&cmd, sizeof(cmd), NULL, NULL, NULL);
}

void bluez_set_scan_param(uint8_t scan_type, uint16_t interval, uint16_t window)
{
	struct bt_hci_cmd_le_set_scan_parameters cmd;
	cmd.type = scan_type;		/* Active scanning */
	cmd.interval = cpu_to_le16(interval);
	cmd.window = cpu_to_le16(window);
	cmd.own_addr_type = 0x00;	/* Use public address */
	cmd.filter_policy = 0x00;

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_SCAN_PARAMETERS,
					&cmd, sizeof(cmd), NULL, NULL, NULL);
}

void bluez_set_scan_enable(uint8_t enable)
{
	struct bt_hci_cmd_le_set_scan_enable cmd;
	cmd.enable = enable;
	cmd.filter_dup = 0x01;

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_SCAN_ENABLE,
					&cmd, sizeof(cmd),
					scan_enable_callback, NULL, NULL);
}

void bluez_set_adv_data(uint8_t const *p_data, uint8_t dlen,
						uint8_t const *p_sr_data, uint8_t srdlen)
{
	struct bt_hci_cmd_le_set_adv_data cmd1;
	struct bt_hci_cmd_le_set_scan_rsp_data cmd2;

	cmd1.len = dlen;
	memcpy(cmd1.data, p_data, dlen);

	cmd2.len = srdlen;
	memcpy(cmd2.data, p_sr_data, dlen);

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_ADV_DATA,
					&cmd1, sizeof(cmd1), NULL, NULL, NULL);

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
					&cmd2, sizeof(cmd2), NULL, NULL, NULL);
}

void bluez_set_adv_param(uint16_t min_interval, uint16_t max_interval, 
						uint8_t adv_type, uint8_t direct_addr_type,
                        uint8_t channel_map)
{
	struct bt_hci_cmd_le_set_adv_parameters cmd;
	cmd.min_interval = cpu_to_le16(min_interval);
	cmd.max_interval = cpu_to_le16(max_interval);
	cmd.type = adv_type;
	cmd.own_addr_type = adv_type;
	cmd.direct_addr_type = direct_addr_type;
	memcpy(cmd.direct_addr, PEER_ADDR, 6);
	cmd.channel_map = channel_map;
	cmd.filter_policy = 0x00;
	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
					&cmd, sizeof(cmd), NULL, NULL, NULL);
}

void bluez_set_adv_start(uint8_t enable)
{
	struct bt_hci_cmd_le_set_adv_enable cmd;
	cmd.enable = enable;
	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_ADV_ENABLE,
					&cmd, sizeof(cmd),
					NULL, NULL, NULL);
}

void bluez_get_bd_addr(uint8_t * addr)
{
	memcpy(addr, device_addr, 6);
}

void * bluez_daemon(void *arg)
{
	int exit_status;
	
	hci_index = *(uint16_t * )arg;

	mainloop_init();
	
	printf("Bluetooth periperhal ver %s , Select hci_index %d\n", VERSION, hci_index);

	hciconfig_hcix_down();

	adv_dev = bt_hci_new_user_channel(hci_index);
	if (!adv_dev) {
		fprintf(stderr, "Failed to open HCI%d for advertiser\n", hci_index);
		pthread_exit(NULL);
	}

	printf("Open HCI%d success!\n", hci_index);

	bt_hci_send(adv_dev, BT_HCI_CMD_RESET, NULL, 0, NULL, NULL, NULL);

	bt_hci_send(adv_dev, BT_HCI_CMD_READ_LOCAL_FEATURES, NULL, 0,
					local_features_callback, NULL, NULL);
	
	bt_hci_send(adv_dev, BT_HCI_CMD_READ_LOCAL_COMMANDS, NULL, 0, NULL, NULL, NULL);
	
	bt_hci_send(adv_dev, BT_HCI_CMD_READ_BD_ADDR, NULL, 0, read_bd_addr_callback, NULL, NULL);
	
	uint8_t evtmask[] = { 0x90, 0xe8, 0x04, 0x02, 0x00, 0x80, 0x00, 0x20 };
	bt_hci_send(adv_dev, BT_HCI_CMD_SET_EVENT_MASK, evtmask, 8,
							NULL, NULL, NULL);

	bt_hci_send(adv_dev, BT_HCI_CMD_LE_READ_LOCAL_FEATURES, NULL, 0,
					adv_le_features_callback, NULL, NULL);

	uint8_t le_evtmask[] = { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
	bt_hci_send(adv_dev, BT_HCI_CMD_LE_SET_EVENT_MASK, le_evtmask, 8,
					le_set_event_mask_callback, NULL, NULL);

	bt_hci_register(adv_dev, BT_HCI_EVT_LE_META_EVENT,
					scan_le_meta_event, NULL, NULL);

	bt_hci_register(adv_dev, BT_HCI_EVT_DISCONNECT_COMPLETE,
					disconnect_event, NULL, NULL);

	exit_status = mainloop_run_with_signal(signal_callback, NULL);

	bt_hci_unref(adv_dev);

done:
	printf("bluez daemon exit_status(%d)\n", exit_status);
	pthread_exit(NULL);
}
