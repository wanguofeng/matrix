#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <time.h>
#include "unqlite.h"

long time_now_ms(void)
{
       struct timeval tv;
       gettimeofday(&tv,NULL);
       return tv.tv_usec/1000;
}

char* time_now_date(void)
{
        time_t timep;
        time(&timep);
        char *s = ctime(&timep);
        //printf("%s",s);
        s[strlen(s) - 6] = '\0';
        return s;
}

static int unqlite_close_safe(unqlite * pdb)
{
    int rc = 0;
    int timeout = 5;
    while ((rc = unqlite_close(pdb)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY){
            usleep(1000);
            timeout --;
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else {
            printf("close err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

static int unqlite_rollback_safe(unqlite * pdb)
{
    int rc = 0;
    int timeout = 5;
    while ((rc = unqlite_rollback(pdb)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY ){
            usleep(1000);
            timeout --;
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else {
            printf("rollback err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

static int unqlite_open_safe(unqlite **pdb, char *file)
{
    int rc = 0;
    int timeout = 5;
    while (( rc = unqlite_open(pdb, file, UNQLITE_OPEN_CREATE)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY){
            usleep(1000);
            timeout --;
	    printf("UNQLITE_BUSY\n");
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else {
            printf("open err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

static int unqlite_del_safe(unqlite *pdb, const void *key, int nkeylen)
{
    int rc = 0;
    int timeout = 5;
    while ((rc = unqlite_kv_delete(pdb, key, nkeylen)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY){
            usleep(1000);
            timeout --;
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else {
            printf("del err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

static int unqlite_store_safe(unqlite *pdb, const void *pkey, int nkeylen, void *pdata, unqlite_int64 ndatalen)
{
    int rc = 0;
    int timeout = 5;
    while ((rc = unqlite_kv_store(pdb, pkey, nkeylen, pdata, ndatalen)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY){
            usleep(1000);
            timeout --;
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else{
            printf("store err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

static int unqlite_commit_safe(unqlite *pdb)
{
    int rc = 0;
    int timeout = 5;
    while ((rc = unqlite_commit(pdb)) != UNQLITE_OK) {
        if( rc == UNQLITE_BUSY){
            usleep(1000);
            timeout --;
	    printf("UNQLITE_BUSY\n");
            if (timeout <= 0) {
                return rc;
            }
            continue;
        }else {
            printf("commit err:%d\n", rc);
            return rc;
        }
    }
    return 0;
}

int settings_unqlite_kv_write(unqlite *pdb, const char *key, uint8_t *data, int len)
{
    int ret = 0;
    if (pdb == NULL) {
        goto ERROR_EXIT;
    }

    printf("before store : %s.%ld\n", time_now_date(), time_now_ms());
    ret = unqlite_store_safe(pdb, key, -1, data, len);
    if(ret != 0){
        printf("store err:%d\n", ret);
        goto ERROR_EXIT;
    }
    printf("after store : %s.%ld\n", time_now_date(), time_now_ms());


ERROR_EXIT:
    if(pdb != NULL) {
        if(ret != 0) {
            ret = unqlite_rollback_safe(pdb);
            if(ret != 0){
                printf("rollback err:%d", ret);
            }
        }
    }
    return ret;
}

int32_t main(int argc, char *argv[])
{
    uint32_t i = 0;
    uint32_t sql_size = 0;
    unqlite *rpl_pdb = NULL;

    if (argc != 4) {
        puts(" usage: ./create_unqlite unqlite.db 100 \n example: ./create_unqlite zblue_self.db 100");
        return 0;
    }

    sql_size = atoi(argv[2]);

    int option = atoi(argv[3]);

    printf("before open : %s.%ld\n", time_now_date(), time_now_ms());
    if (0 != unqlite_open_safe(&rpl_pdb, argv[1])) {
        return -1;
    }
    printf("after open : %s.%ld\n", time_now_date(), time_now_ms());

    srand(time(0));
    int random = rand();

    while(1) {

    	if (rpl_pdb == NULL)
        	return -1;

        char key[64] = {0x00};
	char value[64] = "test unqlite commit speed.";

	if (option == 0) {
		// printf("use update\n");
		snprintf(key, 64, "bt/mesh/RPL/%08x", i++);
	}else {
		// printf("use add\n");
		snprintf(key, 64, "bt/mesh/RPL/%08x_%d", i++, random);
	}
	snprintf(value, 64, "test unqlite commit speed %0d", random);

	// printf("i = %d, key = %s, val = %s\n", i, key, value);
 
        settings_unqlite_kv_write(rpl_pdb, key, value, strlen(value));
	
	if (i >= sql_size) {
		break;
	}
    }

    printf("before commit : %s.%ld\n", time_now_date(), time_now_ms());
    if (0 != unqlite_commit_safe(rpl_pdb)) {
        printf("commit err\n");
    }
    printf("after commit : %s.%ld\n", time_now_date(), time_now_ms());

    printf("before close : %s.%ld\n", time_now_date(), time_now_ms());
    if (rpl_pdb != NULL) {
        unqlite_close_safe(rpl_pdb);
        rpl_pdb = NULL;
    }
    printf("after close : %s.%ld\n", time_now_date(), time_now_ms());

    return 0;
}

