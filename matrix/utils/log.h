
#ifndef _INCLUDE_LOG_H_
#define _INCLUDE_LOG_H_

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <os_info.h>
#include <hex.h>

#define	LOG_EMERG			0	/* System is unusable */
#define	LOG_ALERT			1	/* Action must be taken immediately */
#define	LOG_CRIT			2	/* Critical conditions */
#define	LOG_ERR				3	/* Error conditions */
#define	LOG_WARNING			4	/* Warning conditions */
#define	LOG_NOTICE			5	/* Normal, but significant, condition */
#define	LOG_INFO			6	/* Informational message */
#define	LOG_DEBUG			7	/* Debug-level message */

// #define CONFIG_LOG_LEVEL		LOG_WARNING
// #define CONFIG_APP_NAME		"test"
// #define CONFIG_LOG_SUPPORT_COLOR

#ifdef	CONFIG_LOG_SUPPORT_COLOR
#define	LOG_C_DEFAULT			"\x1B[0m"
#define	LOG_C_BLACK			"\x1B[1;30m"
#define	LOG_C_RED			"\x1B[1;31m"
#define	LOG_C_GREEN			"\x1B[1;32m"
#define	LOG_C_YELLOW			"\x1B[1;33m"
#define	LOG_C_BLUE			"\x1B[1;34m"
#define	LOG_C_MAGENTA			"\x1B[1;35m"
#define	LOG_C_CYAN			"\x1B[1;36m"
#define	LOG_C_WHITE			"\x1B[1;37m"
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

#ifndef CONFIG_LOG_LEVEL
	#define CONFIG_LOG_LEVEL	LOG_DEBUG
#endif

#ifndef CONFIG_APP_NAME
	#define CONFIG_APP_NAME		"matrix"
#endif

#define log_level_printf(level, fmt, arg...)\
	do {\
		if (level <= CONFIG_LOG_LEVEL) {\
			printf("[%s:%d]:" fmt, __FUNCTION__, __LINE__, ##arg);\
		}\
	} while(0)
 
#define	LOGE(fmt, ...)	log_level_printf(LOG_ERR, LOG_C_RED "[%s][%s][%s][E]" fmt LOG_C_DEFAULT, time_date(), application_name(), thread_name(), ##__VA_ARGS__)
#define	LOGW(fmt, ...)	log_level_printf(LOG_WARNING, LOG_C_YELLOW "[%s][%s][%s][W]" fmt LOG_C_DEFAULT, time_date(), application_name(), thread_name(), ##__VA_ARGS__)
#define	LOGI(fmt, ...)	log_level_printf(LOG_INFO, LOG_C_DEFAULT "[%s][%s][%s][I]" fmt LOG_C_DEFAULT, time_date(), application_name(), thread_name(), ##__VA_ARGS__)
#define	LOGD(fmt, ...)	log_level_printf(LOG_DEBUG, LOG_C_DEFAULT "[%s][%s][%s][D]" fmt LOG_C_DEFAULT, time_date(), application_name(), thread_name(), ##__VA_ARGS__)

#define LOG_HEXDUMP_DBG(_data, _length, _str)                                  \
do {                                                                           \
	char str[(_length)*2];                                                     \
	bin2hex((void *)(_data), _length, str, (_length)*2);                       \
	LOGD("%s: %s\n", _str, str);                                             \
} while(0)

#endif
