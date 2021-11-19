#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/prctl.h>
#include <os_info.h>
#include <stdint.h>

char* time_date(void)
{
	static char result[200] = {0x00};
        time_t timep;
	struct timeval tv;

	gettimeofday(&tv,NULL);
	time(&timep);
	tv.tv_usec/1000;
        char *s = ctime(&timep);
	s[strlen(s) - 6] = '\0';
	snprintf(result, sizeof(result), "%s.%ld", s, tv.tv_usec/1000);
        return result;
}

char* thread_name(void) {
	return "none";
}

char* application_name(void) {
	return CONFIG_APP_NAME;
}

#if 0
int main(int argc, const char *argv[])
{
	/* 普通的printf输出 */
	printf("This is my function called %s() ...\n", __func__);
	LOGE("This error log ...\r\n");
	LOGW("This warn log ...\r\n");
	LOGI("This info log ...\r\n");
	LOGD("This debug log ...\r\n");
	return 0;
}
#endif
