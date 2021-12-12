#define CONFIG_LOG_TAG	"demo"
#include <stdio.h>
#include <log.h>
#include <os_info.h>
#include <hex.h>

void main()
{

	LOGD("this is logd");
	LOGI("this is logi");
	LOGW("this is logw");
	LOGE("this is loge");

}
