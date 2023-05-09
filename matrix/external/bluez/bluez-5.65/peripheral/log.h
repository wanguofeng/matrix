
#ifndef _INCLUDE_LOG_H_
#define _INCLUDE_LOG_H_

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdint.h>

#define	LOG_EMERG			0	/* System is unusable */
#define	LOG_ALERT			1	/* Action must be taken immediately */
#define	LOG_CRIT			2	/* Critical conditions */
#define	LOG_ERR				3	/* Error conditions */
#define	LOG_WARNING			4	/* Warning conditions */
#define	LOG_NOTICE			5	/* Normal, but significant, condition */
#define	LOG_INFO			6	/* Informational message */
#define	LOG_DEBUG			7	/* Debug-level message */

#define CONFIG_LOG_SUPPORT_COLOR

#ifdef CONFIG_LOG_SUPPORT_COLOR
#define	LOG_C_DEFAULT			"\x1B[0m"
#define	LOG_C_BLACK				"\x1B[1;30m"
#define	LOG_C_RED				"\x1B[1;31m"
#define	LOG_C_GREEN				"\x1B[1;32m"
#define	LOG_C_YELLOW			"\x1B[1;33m"
#define	LOG_C_BLUE				"\x1B[1;34m"
#define	LOG_C_MAGENTA			"\x1B[1;35m"
#define	LOG_C_CYAN				"\x1B[1;36m"
#define	LOG_C_WHITE				"\x1B[1;37m"

#else
#define	LOG_C_DEFAULT
#define	LOG_C_BLACK
#define	LOG_C_RED
#define	LOG_C_GREEN
#define	LOG_C_YELLOW
#define	LOG_C_BLUE
#define	LOG_C_MAGENTA
#define	LOG_C_CYAN
#define	LOG_C_WHITE
#endif

#ifndef CONFIG_LOG_TAG
	#define CONFIG_LOG_TAG		"matrix"
#endif

#ifndef CONFIG_LOG_LEVEL
	#define CONFIG_LOG_LEVEL	LOG_DEBUG
#endif

#define log_level_printf(level, fmt, arg...)\
	do {\
		if (level <= CONFIG_LOG_LEVEL) {\
			printf(fmt, ##arg);\
		}\
	} while(0)

#define	LOGE(fmt, ...)	log_level_printf(LOG_ERR, LOG_C_RED "[%s][E]" fmt "\n" LOG_C_DEFAULT, CONFIG_LOG_TAG, ##__VA_ARGS__)
#define	LOGW(fmt, ...)	log_level_printf(LOG_WARNING, LOG_C_YELLOW "[%s][W]" fmt "\n" LOG_C_DEFAULT, CONFIG_LOG_TAG, ##__VA_ARGS__)
#define	LOGI(fmt, ...)	log_level_printf(LOG_INFO, LOG_C_CYAN "[%s][I]" fmt "\n" LOG_C_DEFAULT, CONFIG_LOG_TAG, ##__VA_ARGS__)
#define	LOGD(fmt, ...)	log_level_printf(LOG_DEBUG, LOG_C_DEFAULT "[%s][D]" fmt "\n" LOG_C_DEFAULT, CONFIG_LOG_TAG, ##__VA_ARGS__)

extern size_t bin2hex(const uint8_t *buf, size_t buflen, char *str, size_t strlen);

#define LOG_HEXDUMP_DBG(_data, _length, _str)                                  \
do {                                                                           \
	char str[(_length)*2];                                                     \
	bin2hex((void *)(_data), _length, str, (_length)*2);                       \
	LOGD("%s: %s\n", _str, str);                                             \
} while(0)

#endif
