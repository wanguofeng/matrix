#ifndef _INCLUDE_HEX_H_
#define _INCLUDE_HEX_H_

#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>

extern uint8_t u8_to_dec(char *buf, uint8_t buflen, uint8_t value);
extern int char2hex(char c, uint8_t *x);
extern int hex2char(uint8_t x, char *c);
extern size_t bin2hex(const uint8_t *buf, size_t buflen, char *hex, size_t hexlen);
extern size_t hex2bin(const char *hex, size_t hexlen, uint8_t *buf, size_t buflen);
extern uint32_t htoi(char s[]);

#endif
