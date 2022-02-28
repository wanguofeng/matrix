#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>  /* puts() */
#include <stdlib.h> /* exit() */
#include "unqlite.h"

#define DATA_LEN 1024
#define DATA_EXTERN_LEN	32

#define SOURCE_FILE_NAME	"zblue"
#define TARGET_FILE_NAME	"zblue_self.db"

int hex2char(uint8_t x, char *c)
{
        if (x <= 9) {
                *c = x + '0';
        } else  if (x <= 15) {
                *c = x - 10 + 'a';
        } else {
                return -EINVAL;
        }

        return 0;
}

size_t bin2hex(const uint8_t *buf, size_t buflen, char *hex, size_t hexlen)
{
        if ((hexlen + 1) < buflen * 2) {
                return 0;
        }

        for (size_t i = 0; i < buflen; i++) {
                if (hex2char(buf[i] >> 4, &hex[2 * i]) < 0) {
                        return 0;
                }
                if (hex2char(buf[i] & 0xf, &hex[2 * i + 1]) < 0) {
                        return 0;
                }
        }

        hex[2 * buflen] = '\0';
        return 2 * buflen;
}

static inline uint16_t sys_get_le16(const uint8_t src[2])
{
	return ((uint16_t)src[1] << 8) | src[0];
}

/**
 *  @brief Get a 24-bit integer stored in big-endian format.
 *
 *  Get a 24-bit integer, stored in big-endian format in a potentially
 *  unaligned memory location, and convert it to the host endianness.
 *
 *  @param src Location of the big-endian 24-bit integer to get.
 *
 *  @return 24-bit integer in host endianness.
 */
static inline uint32_t sys_get_le24(const uint8_t src[3])
{
	return ((uint32_t)src[2] << 16) | sys_get_le16(&src[0]);
}

#define HEX_DUMP(_data, _length, _str)                                  \
	do {								\
        char str[(_length)*2 + 1];                                      \
        bin2hex((void *)(_data), _length, str, (_length)*2);            \
        str[(_length)*2] = '\0';                                        \
        printf("%s: %s\n", _str, str);					\
	} while(0);

static void *mempbrk(const void *data_, size_t len, const void *accept_, size_t accept_len, size_t value_len)
{
	const char *data = data_, *accept = accept_;

	int i = 0, j = 0;

	for (i = len - accept_len; i >= 0; i --) {

		int ret = 0;

		for (j = 0; j < accept_len; j ++) {

			if (data[i+j] != accept[j]) {
				// printf("can't find %s\n", accept);
				break;
			}
		}

		if (j == accept_len) {

			if (len - i < accept_len + value_len) {
				printf("this %s is invaild\n", accept);
				break;
			}

			printf("find %s\n\n", accept);
			return (void *)&data[i+j];
		}
	}

	return NULL;
}

static void Fatal(unqlite *pDb,const char *zMsg)
{
        if ( pDb ) {
                        const char *zErr;
                        int iLen = 0; /* Stupid cc warning */

                        /* Extract the database error log */
                        unqlite_config(pDb,UNQLITE_CONFIG_ERR_LOG,&zErr,&iLen);
                        if( iLen > 0 ){
                                        /* Output the DB error log */
                                        printf("%s\n", zErr); /* Always null terminated */
                        }
        } else {
                        if( zMsg ){
                                        printf("%s\n", zMsg);
                        }
        }
        /* Manually shutdown the library */
        unqlite_lib_shutdown();
}

int save_meshinfo2unqlite(uint8_t *seq, uint8_t seq_len, uint8_t *iv, uint8_t iv_len) {

	unqlite *pDb;               /* Database handle */
	unqlite_kv_cursor *pCur;    /* Cursor handle */
	int i,rc;

	/* Open our database */
	rc = unqlite_open(&pDb, TARGET_FILE_NAME, UNQLITE_OPEN_CREATE);
	if( rc != UNQLITE_OK ){
		Fatal(0,"Out of memory");
	}

	/* Store some records */
	rc = unqlite_kv_store(pDb, "bt/mesh/Seq", -1, seq, seq_len);
	if( rc != UNQLITE_OK ){
		/* Insertion fail, extract database error log and exit */
		Fatal(pDb,0);
	}

	/* Store some records */
	rc = unqlite_kv_store(pDb, "bt/mesh/IV", -1, iv, iv_len);
	if( rc != UNQLITE_OK ){
		/* Insertion fail, extract database error log and exit */
		Fatal(pDb,0);
	}

	/* Auto-commit the transaction and close our database */
	unqlite_close(pDb);
}

int transfer_meshinfo_storage(uint8_t *seq, uint8_t seq_len, uint8_t *iv, uint8_t iv_len)
{
	FILE *fp;
	long total_len = 0;
	long remain_len = 0;
	int i = 0;

	bool is_seq_finded = false;
	bool is_iv_finded = false;
	uint32_t seq_number = 0;


	unsigned char data[DATA_LEN + DATA_EXTERN_LEN] = {0x00};

	fp = fopen(SOURCE_FILE_NAME, "r");

	if (fp == NULL) {
		printf("fopen zblue file error.\n");
		return -1;
	}

	if (0 != fseek(fp, 0, SEEK_END)) {
		printf("fseek zblue file error.\n");
		fclose(fp);
   		return -1;
	}

	total_len = ftell(fp);

	printf("total len = %ld\n\n", total_len);

	remain_len = total_len;

	do {
		int ret = 0;
		i++;

		if (remain_len > DATA_LEN) {
			ret = fseek(fp, -DATA_LEN * i, SEEK_END);
		} else {
			ret = fseek(fp, 0, SEEK_SET);
		}

		if (0 != ret) {
			printf("fseek zblue file error.\n");
			fclose(fp);
			return -1;
		}

		remain_len = ftell(fp);

		long read_len = fread(data, 1, DATA_LEN + DATA_EXTERN_LEN, fp);
		// printf("read_len = %ld\n", read_len);
		// printf("remain_len = %ld\n\n", remain_len);
		// HEX_DUMP(data, read_len, "hex dump");

		if (!is_iv_finded) {

			void *p = mempbrk(data, read_len, "IV=", strlen("IV="), iv_len);

			if (NULL != p) {
				HEX_DUMP(p, iv_len, "iv struct");
				memcpy(iv, p, iv_len);
				is_iv_finded = true;
			}
		}

		void *p = mempbrk(data, read_len, "Seq=", strlen("Seq="), seq_len);
		
		if (NULL != p) {

			HEX_DUMP(p, seq_len, "seq number");

			if (seq_number <= sys_get_le24(p)) {
				seq_number = sys_get_le24(p);
				printf("seq number = %x\n", seq_number);
				memcpy(seq, p, seq_len);
			}

			is_seq_finded = true;
		}

		if (is_seq_finded && is_iv_finded) {
			break;
		}

	} while (remain_len != 0);

	fclose(fp);

	if ((is_iv_finded == false) || (is_seq_finded == false)) {
		return -1;
	}

	return 0;
}

int main()
{
	if ((access(SOURCE_FILE_NAME, F_OK)) == 0) {

		printf("%s is exist\n", SOURCE_FILE_NAME);

		uint8_t seq[3] = {0x00};
		uint8_t iv[5] = {0x00};

		if (0 == transfer_meshinfo_storage(seq, sizeof(seq), iv, sizeof(iv))) {

			printf("iv struct = %02x%02x%02x%02x%02x\n", iv[0], iv[1], iv[2], iv[3], iv[4]);
			printf("seq number = %02x%02x%02x\n", seq[0], seq[1], seq[2]);

			save_meshinfo2unqlite(seq, sizeof(seq), iv, sizeof(iv));
		}

		if (0 == remove(SOURCE_FILE_NAME)) {
			printf("remove %s success\n", SOURCE_FILE_NAME);
		}
	}

	return 0;
}

