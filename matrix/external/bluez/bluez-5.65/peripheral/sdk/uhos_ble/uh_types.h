/**
 * @copyright Copyright (c) 2021, Haier.Co, Ltd.
 * @file uh_types.h
 * @author  tangjinqi@haier.com)
 * @brief
 * @date 2021-09-27
 *
 * @par History:
 * <table>
 * <tr><th>Date         <th>version <th>Author  <th>Description
 * <tr><td>2021-09-27   <td>1.0     <td>tangjinqi        <td>init version
 * </table>
 */

#ifndef __UH_TYPES_H__
#define __UH_TYPES_H__

#include <stdint.h>

#ifdef __cplusplus
#define UHOS_NULL 0L
#else
#define UHOS_NULL ((void *)0)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char      uhos_u8;
typedef signed char        uhos_s8;
typedef unsigned short     uhos_u16;
typedef signed short       uhos_s16;
typedef signed int         uhos_s32;
typedef unsigned int       uhos_u32;
typedef unsigned long long uhos_u64;
typedef signed long long   uhos_s64;
typedef char               uhos_char;
typedef void               uhos_void;
typedef unsigned char      uhos_bool;
typedef float              uhos_float; 
typedef double             uhos_double;

typedef intptr_t           uhos_intptr;
typedef uintptr_t          uhos_uintptr;


#define UHOS_TRUE  1
#define UHOS_FALSE 0


#define uhos_register register
#define UHOS_SUCCESS 0
#define UHOS_FAILURE (-1)

#ifdef __cplusplus
}
#endif

#endif /*__UH_TYPES_H__*/