#ifndef TYPES_H
#define TYPES_H

#include <gmp.h>

#define PRINT   1
#define TWO     2

#define BIT_SET(base, index)    do{(*base) |= (1 << (index));}while(0)
#define BIT_CLEAR(base, index)  do{(*base) &= ~(1 << (index));}while(0)
#define BIT_CHECK(base, index)  (((*base) & (1 << (index))) > 0)

#define SWAP(a, b)  do{void * _tmp = a; a = b; b = _tmp;}while(0)
#define INT(p)  ((p) - '0')
#define CHAR(p) ((p) + '0')

#define __maybe_unused  __attribute__((unused))

typedef void * ADDR;

typedef enum
{
    FALSE = 0,
    TRUE = 1
}BOOL;

typedef struct{
    int n;
    int p;
}tCombValues;

typedef struct
{
    int LBit;
    int NBit;
    tCombValues combValues;
    unsigned char *msg;
    int msgLen;
    ADDR msgHash;
    mpz_t msgHashValue;
    ADDR IP;
    ADDR keys;
    ADDR signature;
}tLamport;

#endif //TYPES_H
