#ifndef TYPES_H
#define TYPES_H

#include <gmp.h>
#include <time.h>
#include <openssl/aes.h>

#define PRINT   0
#define DEBUG   0
#define CHANGE_BIT_SERVICE 0

#define BIT_SET(base, index)    do{(*base) |= (1 << (index));}while(0)
#define BIT_CLEAR(base, index)  do{(*base) &= ~(1 << (index));}while(0)
#define BIT_CHECK(base, index)  (((*base) & (1 << (index))) > 0)

#define GET_ADDR(addr, i, byte)                 ( (ADDR) (((char *)(addr)) + ((i) * (byte))) )

#define SWAP(a, b)  do{void * _tmp = a; a = b; b = _tmp;}while(0)
#define INT(p)  ((p) - '0')
#define CHAR(p) ((p) + '0')

#define __maybe_unused  __attribute__((unused))

typedef void * ADDR;
typedef unsigned char INT1;
typedef signed int INT4;
typedef unsigned int UINT4;

typedef enum
{
    FALSE = 0,
    TRUE = 1
}BOOL;

typedef struct{
    int n;
    int p;
}tCombValues;

typedef struct{
    ADDR msg;
    unsigned int msgLen;
}msg_node;

typedef struct{
    ADDR IP;
    UINT4 increment_value;
}tIP_values;

typedef struct
{
    tCombValues combValues;
    msg_node *messages;
    ADDR msgHash;
    tIP_values ip_values;
    ADDR pre_images;
    ADDR hash_images;
    ADDR signature;
    int numberOfMsg;
    AES_KEY aes_key;
}tLamport;




#endif //TYPES_H
