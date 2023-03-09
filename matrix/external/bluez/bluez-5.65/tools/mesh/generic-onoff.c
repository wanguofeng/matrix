// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019-2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh-defs.h"
#include "mesh/util.h"
#include "mesh/crypto.h"

#include "tools/mesh/util.h"
#include "tools/mesh/model.h"
#include "tools/mesh/keys.h"
#include "tools/mesh/mesh-db.h"
#include "tools/mesh/remote.h"
#include "tools/mesh/generic-onoff-model.h"
#include "tools/mesh/generic-onoff.h"

#define NO_RESPONSE 0xFFFFFFFF

/* Default timeout for getting a response to a sent config command (seconds) */
#define DEFAULT_TIMEOUT 2

struct generic_onoff_client_cmd {
	uint32_t opcode;
	uint32_t rsp;
	const char *desc;
};

struct pending_req {
	struct l_timeout *timer;
	const struct generic_onoff_client_cmd *cmd;
	uint16_t addr;
};

static struct l_queue *requests;

static void *send_data;
static model_send_msg_func_t send_msg;

static uint32_t rsp_timeout = DEFAULT_TIMEOUT;
static uint16_t target = UNASSIGNED_ADDRESS;
static uint32_t parms[8];
static uint8_t transition_id = 0;

static struct generic_onoff_client_cmd cmds[] = {
	{ OP_GENERIC_ONOFF_GET, OP_GENERIC_ONOFF_STATUS, "GenericOnOffGet" },
	{ OP_GENERIC_ONOFF_SET, OP_GENERIC_ONOFF_STATUS, "GenericOnOffSet" },
	{ OP_GENERIC_ONOFF_SET_UNACK, NO_RESPONSE, "GenericOnOffSetUnack" },
	{ OP_GENERIC_ONOFF_STATUS, NO_RESPONSE, "GenericOnOffStatus" },
};

static const struct generic_onoff_client_cmd *get_cmd(uint32_t opcode)
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
	const struct generic_onoff_client_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return "Unknown";

	return cmd->desc;
}

static void free_request(void *a)
{
	struct pending_req *req = a;

	l_timeout_remove(req->timer);
	l_free(req);
}

static struct pending_req *get_req_by_rsp(uint16_t addr, uint32_t rsp)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(requests);

	for (; entry; entry = entry->next) {
		struct pending_req *req = entry->data;

		if (req->addr == addr && req->cmd->rsp == rsp)
			return req;
	}

	return NULL;
}

static void wait_rsp_timeout(struct l_timeout *timeout, void *user_data)
{
	struct pending_req *req = user_data;

	bt_shell_printf("No response for \"%s\" from %4.4x\n",
						req->cmd->desc, req->addr);

	l_queue_remove(requests, req);
	free_request(req);
}

static void add_request(uint32_t opcode)
{
	struct pending_req *req;
	const struct generic_onoff_client_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return;

	req = l_new(struct pending_req, 1);
	req->cmd = cmd;
	req->addr = target;
	req->timer = l_timeout_create(rsp_timeout,
				wait_rsp_timeout, req, NULL);
	l_queue_push_tail(requests, req);
}

static void print_remaining_time(uint8_t remaining_time)
{
	uint8_t step = (remaining_time & 0xc0) >> 6;
	uint8_t count = remaining_time & 0x3f;
	int secs = 0, msecs = 0, minutes = 0, hours = 0;

	switch (step) {
	case 0:
		msecs = 100 * count;
		secs = msecs / 1000;
		msecs -= (secs * 1000);
		break;
	case 1:
		secs = 1 * count;
		minutes = secs / 60;
		secs -= (minutes * 60);
		break;

	case 2:
		secs = 10 * count;
		minutes = secs / 60;
		secs -= (minutes * 60);
		break;
	case 3:
		minutes = 10 * count;
		hours = minutes / 60;
		minutes -= (hours * 60);
		break;

	default:
		break;
	}

	bt_shell_printf("\n\t\tRemaining time: %d hrs %d mins %d secs %d"
			" msecs\n", hours, minutes, secs, msecs);

}

static bool msg_recvd(uint16_t src, uint16_t app_idx,
						uint8_t *data, uint16_t len)
{
	uint32_t opcode;
	int n;
	const struct generic_onoff_client_cmd *cmd;
	struct pending_req *req;

	if (mesh_opcode_get(data, len, &opcode, &n)) {
		len -= n;
		data += n;
	} else
		return false;

	req = get_req_by_rsp(src, opcode);
	if (req) {
		cmd = req->cmd;
		l_queue_remove(requests, req);
		free_request(req);
	} else
		cmd = NULL;

	bt_shell_printf("On Off Model Message received (%d) opcode %x\n",
								len, opcode);
	switch (opcode) {
		case OP_GENERIC_ONOFF_STATUS:
			if (len != 1 && len != 3)
				break;

			bt_shell_printf("Node %4.4x: Off Status present = %s\n",
							src, data[0] ? "ON" : "OFF");

			if (len == 3) {
				bt_shell_printf(", target = %s\n",
						data[1] ? "ON" : "OFF");
				print_remaining_time(data[2]);
			}
			break;
		default:
			return false;
	}

	return true;
}

static uint32_t read_input_parameters(int argc, char *argv[])
{
	uint32_t i;

	if (!argc)
		return 0;

	--argc;
	++argv;

	if (!argc || argv[0][0] == '\0')
		return 0;

	for (i = 0; i < L_ARRAY_SIZE(parms) && i < (uint32_t) argc; i++) {
		if (sscanf(argv[i], "%x", &parms[i]) != 1)
			break;
	}

	return i;
}

static void cmd_timeout_set(int argc, char *argv[])
{
	if (read_input_parameters(argc, argv) != 1)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	rsp_timeout = parms[0];

	bt_shell_printf("Timeout to wait for remote node's response: %d secs\n",
								rsp_timeout);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_dst_set(int argc, char *argv[])
{
	uint32_t dst;
	char *end;

	dst = strtol(argv[1], &end, 16);

	if (end != (argv[1] + 4)) {
		bt_shell_printf("Bad unicast address %s: "
				"expected format 4 digit hex\n", argv[1]);
		target = UNASSIGNED_ADDRESS;

		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Generic OnOff node %4.4x\n", dst);
	target = dst;
	set_menu_prompt("on/off", argv[1]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool generic_onoff_send(uint8_t *buf, uint16_t len, uint32_t opcode)
{
	const struct generic_onoff_client_cmd *cmd;
	bool res;

	if (IS_UNASSIGNED(target)) {
		bt_shell_printf("Destination not set\n");
		return false;
	}

	cmd = get_cmd(opcode);
	if (!cmd)
		return false;

	if (get_req_by_rsp(target, cmd->rsp)) {
		bt_shell_printf("Another command is pending\n");
		return false;
	}

	uint16_t app_idx = mesh_db_node_model_bind_app_idx(target, target, false, GENERIC_ONOFF_SERVER_MODEL_ID);

	bt_shell_printf("Model ID\t%4.4x \"%s\"\n", GENERIC_ONOFF_SERVER_MODEL_ID,
					sig_model_string(GENERIC_ONOFF_SERVER_MODEL_ID));
	bt_shell_printf("AppIdx\t\t%u (0x%3.3x)\n ", app_idx, app_idx);

	res = send_msg(send_data, target, app_idx, buf, len);
	if (!res)
		bt_shell_printf("Failed to send \"%s\"\n", opcode_str(opcode));

	if (cmd->rsp != NO_RESPONSE)
		add_request(opcode);

	return res;
}

static void cmd_generic_onoff_set(int argc, char *argv[])
{
	uint16_t n;
	uint8_t msg[8];
	uint32_t parm_cnt;

	n = mesh_opcode_set(OP_GENERIC_ONOFF_SET, msg);

	parm_cnt = read_input_parameters(argc, argv);
	if (parm_cnt != 1) {
		bt_shell_printf("bad arguments");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	msg[n++] = parms[0];

	transition_id ++;
	msg[n++] = transition_id;

	if (!generic_onoff_send(msg, n, OP_GENERIC_ONOFF_SET))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_generic_onoff_set_unack(int argc, char *argv[])
{
	uint16_t n;
	uint8_t msg[8];
	uint32_t parm_cnt;

	n = mesh_opcode_set(OP_GENERIC_ONOFF_SET_UNACK, msg);

	parm_cnt = read_input_parameters(argc, argv);
	if (parm_cnt != 1) {
		bt_shell_printf("bad arguments");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	msg[n++] = parms[0];

	transition_id = (transition_id ++) % 127;
	msg[n++] = transition_id;

	if (!generic_onoff_send(msg, n, OP_GENERIC_ONOFF_SET_UNACK))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_generic_onoff_get(int argc, char *argv[])
{
	uint16_t n;
	uint8_t msg[32];

	n = mesh_opcode_set(OP_GENERIC_ONOFF_GET, msg);

	if (!generic_onoff_send(msg, n, OP_GENERIC_ONOFF_GET))
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool tx_setup(model_send_msg_func_t send_func, void *user_data)
{
	if (!send_func)
		return false;

	send_msg = send_func;
	send_data = user_data;

	return true;
}

static const struct bt_shell_menu generic_onoff_client_menu = {
	.name = "onoff",
	.desc = "GenericOnOff Model Submenu",
	.entries = {
	{"target", "<unicast>", cmd_dst_set,
				"Set target node to configure"},
	{"timeout", "<seconds>", cmd_timeout_set,
				"Set response timeout (seconds)"},
	{"onoff-set", "<0/1>", cmd_generic_onoff_set,
				"Set Generic OnOff State"},
	{"onoff-set-unack", "<0/1>", cmd_generic_onoff_set_unack,
				"Set Generic OnOff State"},
	{"onoff-get", NULL, cmd_generic_onoff_get,
				"Get Generic OnOff State"},
	{} },
};

static struct model_info generic_onoff_client_info = {
	.ops = {
		.set_send_func = tx_setup,
		.set_pub_func = NULL,
		.recv = msg_recvd,
		.bind = NULL,
		.pub = NULL
	},
	.mod_id = GENERIC_ONOFF_CLIENT_MODEL_ID,
	.vendor_id = VENDOR_ID_INVALID
};

struct model_info *generic_onoff_init(void)
{
	requests = l_queue_new();
	bt_shell_add_submenu(&generic_onoff_client_menu);

	return &generic_onoff_client_info;
}

void generic_onoff_cleanup(void)
{
	l_queue_destroy(requests, free_request);
}
