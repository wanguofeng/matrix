#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "lib/bluetooth.h"
#include "adapter/utils.h"
#include "lib/mgmt.h"

#define CONFIG_LOG_TAG "bluez_stack/utils"
#include "adapter/log.h"

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

const char *opcode_str(uint32_t opcode)
{
	const struct mgmt_cmd *cmd;

	cmd = get_cmd(opcode);
	if (!cmd)
		return "Unknown";

	return cmd->desc;
}

const char *get_adv_pdu_type(uint16_t adv_type)
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

uint8_t le16(uint8_t data)
{
	return (data * 16 / 10);
}

size_t bin2hex(const uint8_t *buf, size_t buflen, char *str,
								size_t strlen)
{
	size_t i;

	for (i = 0; i < buflen && i < (strlen / 2); i++)
		sprintf(str + (i * 2), "%02x", buf[i]);

	return i;
}

char *system_config_type_str(uint16_t type)
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

void print_mgmt_tlv(void *data, void *user_data)
{
	const struct mgmt_tlv *entry = data;
	char buf[256];

	bin2hex(entry->value, entry->length, buf, sizeof(buf));
	LOGD("Type: 0x%04x\tLength: %02hhu\tValue: %s\tName: %s", entry->type, entry->length,
							buf, system_config_type_str(entry->type));
}

char *eir_get_name(const uint8_t *eir, uint16_t eir_len)
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

unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len)
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


const char *typestr(uint8_t type)
{
	static const char *str[] = { "BR/EDR", "LE Public", "LE Random" };

	if (type <= BDADDR_LE_RANDOM)
		return str[type];

	return "(unknown)";
}
