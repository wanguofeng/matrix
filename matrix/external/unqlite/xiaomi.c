/*
 * Compile this file together with the UnQLite database engine source code
 * to generate the executable. For example: 
 *  gcc -W -Wall -O6 unqlite_kv_intro.c unqlite.c -o unqlite_kv
*/
/*
 * This simple program is a quick introduction on how to embed and start
 * experimenting with UnQLite without having to do a lot of tedious
 * reading and configuration.
 *
 * Introduction to the Key/Value Store Interfaces:
 *
 * UnQLite is a standard key/value store similar to BerkeleyDB, Tokyo Cabinet, LevelDB, etc.
 * But, with a rich feature set including support for transactions (ACID), concurrent reader, etc.
 * Under the KV store, both keys and values are treated as simple arrays of bytes, so content
 * can be anything from ASCII strings, binary blob and even disk files.
 * The KV store layer is presented to host applications via a set of interfaces, these includes:
 * unqlite_kv_store(), unqlite_kv_append(), unqlite_kv_fetch_callback(), unqlite_kv_append_fmt(),
 * unqlite_kv_delete(), unqlite_kv_fetch(), etc.
 *
 * For an introduction to the UnQLite C/C++ interface, please refer to:
 *        http://unqlite.org/api_intro.html
 * For the full C/C++ API reference guide, please refer to:
 *        http://unqlite.org/c_api.html
 * UnQLite in 5 Minutes or Less:
 *        http://unqlite.org/intro.html
 * The Architecture of the UnQLite Database Engine:
 *        http://unqlite.org/arch.html
 * For an introduction to the UnQLite cursor interface, please refer to:
 *        http://unqlite.org/c_api/unqlite_kv_cursor.html
 * For an introduction to Jx9 which is the scripting language which power
 * the Document-Store interface to UnQLite, please refer to:
 *        http://unqlite.org/jx9.html
 */
/* $SymiscID: unqlite_kv_intro.c v1.0 FreeBSD 2013-05-14 10:17 stable <chm@symisc.net> $ */
/* 
 * Make sure you have the latest release of UnQLite from:
 *  http://unqlite.org/downloads.html
 */
#include <stdio.h>  /* puts() */
#include <stdlib.h> /* exit() */
/* Make sure this header file is available.*/
#include "unqlite.h"
#include <string.h>
#include <errno.h>
/*
 * Banner.
 */
static const char zBanner[] = {
	"============================================================\n"
	"UnQLite Key/Value Store Intro                              \n"
	"                                         http://unqlite.org/\n"
	"============================================================\n"
};

#define CONFIG_SETTINGS_UNQLITE_KV_SIZE 128

/* Forward declaration: Data consumer callback */
static int data_consumer_callback(const void *pData,unsigned int nDatalen,void *pUserData /* Unused */);
static void Fatal(unqlite *pDb,const char *zMsg);

static char unqlite_load_data[CONFIG_SETTINGS_UNQLITE_KV_SIZE];
static short unqlite_load_data_len = 0;

int hex2char(unsigned char x, char *c)
{
	if (x <= 9) {
		*c = x + '0';
	} else  if (x <= 15) {
		*c = x - 10 + 'A';
	} else {
		return -EINVAL;
	}

	return 0;
}

int bin2hex(const unsigned char *buf, int buflen, char *hex, int hexlen)
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

#define HEXDUMP(_data, _length, _str)                                  \
do {                                                                           \
        char str[(_length)*2 + 1];                                                     \
        bin2hex((void *)(_data), _length, str, (_length)*2);                       \
        str[(_length)*2] = '\0';                                                                                \
        printf("%s: %s\n", _str, str);                                             \
} while(0)


int main(int argc,char *argv[])
{
	unqlite *pDb;               /* Database handle */
	unqlite_kv_cursor *pCur;    /* Cursor handle */
	int i,rc;

	puts(zBanner);

	/* Open our database */
	rc = unqlite_open(&pDb,argc > 1 ? argv[1] /* On-disk DB */ : ":mem:" /* In-mem DB */,UNQLITE_OPEN_CREATE);
	if( rc != UNQLITE_OK ){
		Fatal(0,"Out of memory");
	}
	
	puts("Done...Starting the iteration process");
	/* Allocate a new cursor instance */
	rc = unqlite_kv_cursor_init(pDb,&pCur);
	if( rc != UNQLITE_OK ){
		Fatal(0,"Out of memory");
	}
	/* Point to the first record */
	unqlite_kv_cursor_first_entry(pCur);
	
	/* Iterate over the entries */
	while( unqlite_kv_cursor_valid_entry(pCur) ){
		int nKeyLen;
		unqlite_int64 nDataLen;
		
		/* Consume the key */
		unqlite_kv_cursor_key(pCur,0,&nKeyLen); /* Extract key length */
		unqlite_kv_cursor_key_callback(pCur,data_consumer_callback,0);
		printf("key value => %s, len = %d\n", unqlite_load_data, unqlite_load_data_len);	
		/* Consume the data */
		
		unqlite_kv_cursor_data(pCur,0,&nDataLen);
		unqlite_kv_cursor_data_callback(pCur,data_consumer_callback,0);
		printf("Data value len ==> %lld ",nDataLen);
		HEXDUMP(unqlite_load_data, unqlite_load_data_len,"Data value ");
		printf("\n\n");
		/*
		*/

		/* Point to the next entry */
		unqlite_kv_cursor_next_entry(pCur);

	}
	/* Finally, Release our cursor */
	unqlite_kv_cursor_release(pDb,pCur);
	
	/* Auto-commit the transaction and close our database */
	unqlite_close(pDb);
	return 0;
}

#ifdef __WINNT__
#include <Windows.h>
#else
/* Assume UNIX */
#include <unistd.h>
#endif
/*
 * The following define is used by the UNIX build process and have
 * no particular meaning on windows.
 */
#ifndef STDOUT_FILENO
#define STDOUT_FILENO	1
#endif
/*
 * Data consumer callback [unqlite_kv_fetch_callback(), unqlite_kv_cursor_key_callback(), etc.).
 * 
 * Rather than allocating a static or dynamic buffer (Inefficient scenario for large data).
 * The caller simply need to supply a consumer callback which is responsible of consuming
 * the record data perhaps redirecting it (i.e. Record data) to its standard output (STDOUT),
 * disk file, connected peer and so forth.
 * Depending on how large the extracted data, the callback may be invoked more than once.
 */

/*
 * Extract the database error log and exit.
 */
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

static int data_consumer_callback(const void *pData,unsigned int nDatalen,void *pUserData /* Unused */)
{
        // printf("pData = %s, nDatalen = %d\n", pData, nDatalen);
        memset(unqlite_load_data, 0x00, CONFIG_SETTINGS_UNQLITE_KV_SIZE);
        if (nDatalen >= CONFIG_SETTINGS_UNQLITE_KV_SIZE)
                nDatalen = CONFIG_SETTINGS_UNQLITE_KV_SIZE - 1;
        memcpy(unqlite_load_data, pData, nDatalen);
        unqlite_load_data_len = nDatalen;
        if( nDatalen < 0 ){
                        /* Abort processing */
                        return UNQLITE_ABORT;
        }

        return UNQLITE_OK;
}
