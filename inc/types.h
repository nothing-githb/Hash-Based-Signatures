#ifndef TYPES_H
#define TYPES_H

#include <gmp.h>

#define PRINT   0
#define DEBUG   0
#define CHANGE_BIT_SERVICE 1

#define BIT_SET(base, index)    do{(*base) |= (1 << (index));}while(0)
#define BIT_CLEAR(base, index)  do{(*base) &= ~(1 << (index));}while(0)
#define BIT_CHECK(base, index)  (((*base) & (1 << (index))) > 0)

#define SWAP(a, b)  do{void * _tmp = a; a = b; b = _tmp;}while(0)
#define INT(p)  ((p) - '0')
#define CHAR(p) ((p) + '0')

#define __maybe_unused  __attribute__((unused))

typedef void * ADDR;
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

typedef struct
{
    tCombValues combValues;
    msg_node *messages;
    ADDR msgHash;
    ADDR IP;
    ADDR pre_images;
    ADDR hash_images;
    ADDR signature;
    int numberOfMsg;
}tLamport;

#endif //TYPES_H
