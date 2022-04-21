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

#include "unqlite.h"

#define MAGIC_STR "bt/mesh/"
#define MAGIC_LEN 8
#define HEADER_LEN 2
#define MAX_RECORD_LEN  256

unqlite *rpl_pdb = NULL;
unqlite *self_pdb = NULL;

static inline uint16_t sys_get_le16(const uint8_t src[2])
{
	return ((uint16_t)src[1] << 8) | src[0];
}

static inline uint32_t sys_get_le24(const uint8_t src[3])
{
	return ((uint32_t)src[2] << 16) | sys_get_le16(&src[0]);
}

static bool settings_unqlite_is_rpl_database(const char *name)
{
    if (!strncmp(name, "bt/mesh/RPL", strlen("bt/mesh/RPL"))) {
        return true;
    }
    return false;
}

static bool settings_unqlite_is_seq_number_database(const char *name)
{
    if (!strncmp(name, "bt/mesh/Seq", strlen("bt/mesh/Seq"))) {
        return true;
    }
    return false;
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

int settings_unqlite_kv_write(unqlite *pdb, const char *key, uint8_t *data, int len)
{
    int ret = 0;
    if (pdb == NULL) {
        goto ERROR_EXIT;
    }

    ret = unqlite_store_safe(pdb, key, -1, data, len);
    if(ret != 0){
        printf("store err:%d\n", ret);
        goto ERROR_EXIT;
    }

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

int unqlite_init(char * src_path)
{
    int rc = 0;
    char target_path[64] = {0x00};
    snprintf(target_path, sizeof(target_path) - 10, "%s_self.db", src_path);

    rc = unqlite_open_safe(&self_pdb, target_path);
    if (rc != 0) {
        goto END;
    }

    memset(target_path, 0x00, sizeof(target_path));
    snprintf(target_path, sizeof(target_path) - 10, "%s_rpl.db", src_path);
    
    rc = unqlite_open_safe(&rpl_pdb, target_path);
    if (rc != 0) {
        goto END;
    }

    if (rpl_pdb == NULL || self_pdb == NULL) {
        rc = -1;
        goto END;
    }
        
END:
    return 0;
}

int unqlite_deinit()
{
    if (self_pdb != NULL) {
        if (0 != unqlite_close_safe(self_pdb)) {
            printf("close self.db fail\n");
        }
        self_pdb = NULL;
    }

    if (rpl_pdb != NULL) {
        if (0 != unqlite_close_safe(rpl_pdb)) {
            printf("close self.db fail\n");
        }
        rpl_pdb = NULL;
    }
}

int unqlite_write_kv(const char *key, uint8_t *data, int len)
{
    static uint32_t seq_number = 0;

    if (settings_unqlite_is_rpl_database(key)) {
        return settings_unqlite_kv_write(rpl_pdb, key, data, len);
    } else {
        if ((settings_unqlite_is_seq_number_database(key)) && (len == 3)) {
            if (seq_number >= sys_get_le24(data)) {
                return 0;
            }
            seq_number = sys_get_le24(data);
        }
        return settings_unqlite_kv_write(self_pdb, key, data, len);
    }
}

char *find_first_prefix(char *buf, uint32_t buf_len)
{
    int i;
    for(i = HEADER_LEN; i < buf_len - MAGIC_LEN; i++){
        if(strncmp(&buf[i], MAGIC_STR, MAGIC_LEN) == 0){
            return &buf[i-HEADER_LEN];
        }
    }
    return NULL;
}

char* parser_config(char *buf, uint32_t buf_len)
{
    uint32_t len = 0, remaining = 0;
    int i = 0, j;
    uint8_t *ptr = buf;
    uint8_t *start = NULL, *next = NULL, *sep = NULL;
    uint8_t *end = buf + buf_len;

    while(ptr < end){
        len = ptr[0] + (ptr[1]<<8);
        start = ptr + HEADER_LEN;
        remaining = end - start;

        if(remaining < len){
            printf("1\n");
            return ptr;
        }

        next = NULL;
        sep = NULL;
        for(i = HEADER_LEN+1; i < remaining - MAGIC_LEN; i++){
            if(sep == NULL && start[i] == '='){
                sep = &start[i];
            }
            if(strncmp(&start[i], MAGIC_STR, MAGIC_LEN) == 0){
                next = &start[i - HEADER_LEN];
                break;
            }
        }

        if(next == NULL){
            printf("2\n");
            if(remaining > MAX_RECORD_LEN){
                return end - MAX_RECORD_LEN;
            }else{
                return ptr;
            }
        }

        if(len == next - start){
            if(sep == NULL){
                printf("not found sep\n");
            }else{
                printf("len=%d, %02x %02x %.*s=\n",
                    len, ptr[1], ptr[0],(int)(sep - start), start);

                char key[64] = {0x00};
                uint8_t value[64] = {0x00};

                memcpy(key , start, (int)(sep - start));
                memcpy(value, &start[sep - start + 1], len - (sep - start + 1));

                unqlite_write_kv(key, value, len - (sep - start + 1));

                for(j = sep - start + 1; j < len; j++){
                    printf("%02x ", start[j]);
                }

                printf("\n");
            }
        }else{
            if(sep == NULL){
                printf("not found sep\n");
                printf("**********error, %.*s=\n", len, start);
                for(j = 0; j < next - start; j++){
                    printf("%02x ", start[j]);
                }
                printf("\n");
            }else{
                printf("**********error, %.*s=", (int)(sep - start), start);
                for(j = sep - start + 1; j < next - start; j++){
                    printf("%02x ", start[j]);
                }
                printf("\n");
            }
        }
        ptr = next;
    }
    printf("error\n");
    return end;
}

int transfer_settings_store(char * src_path)
{
    uint32_t total_len = 0;
    long int read_len = 4096;
    uint32_t offset = 0;
    char buffer[4096];
    int rc = 0;

    FILE *fp = fopen(src_path, "rb");

    if(fp == NULL){
        rc = -1;
        goto ERROR;
    }

    if(fseek(fp, 0, SEEK_SET) < 0){
        rc = -1;
        goto ERROR;
    }

    rc = unqlite_init(src_path);
    if (rc != 0) {
        goto ERROR;
    }

    while(1) {
        read_len = fread(buffer + offset, 1, sizeof(buffer) - offset, fp);
        if(read_len > 0){
            total_len = read_len + offset;
            if(total_len < MAGIC_LEN + HEADER_LEN){
                printf("eof\n");
                break;
            }else{
                printf("total_len=%d\n", total_len);
                char *ptr = find_first_prefix(buffer, total_len);
                if(ptr != NULL){
                    char *pos = parser_config(ptr, total_len - (ptr - buffer));
                    offset = total_len - (pos - buffer);
                    memmove(buffer, pos, offset);
                    buffer[offset] = '\0';
                    printf("offset:%d, %02x %02x %s=\n", offset, buffer[1], buffer[0], &buffer[2]);
                }
            }
        }else{
            printf("unknown for last line, ignore, %d\n", (int)read_len);
            break;
        }
    }

    rc = unqlite_deinit();
    if (rc != 0) {
        goto ERROR;
    }

ERROR:
    if (fp) {
        fclose(fp);
    }
    return rc;
}

int transfer_stack_settings(char * src_path)
{
    int rc = 0;

    rc = access(src_path, F_OK);
    if (rc != 0) {
        printf("%s is not exist\n", src_path);
        goto END;
    }

    rc = transfer_settings_store(src_path);
    if (rc != 0) {
        printf("transfer %s fail", src_path);
        goto END;
    }

    rc = remove(src_path);
    if (rc != 0) {
        printf("remove %s fail\n", src_path);
        goto END;
    }

END:
    return rc;
}

int main(int argc, char *argv[])
{
    transfer_stack_settings("./zblue");
    return 0;
}

