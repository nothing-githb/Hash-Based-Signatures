#ifndef TYPES_H
#define TYPES_H

#include <gmp.h>
#include <time.h>

#define PRINT   0
#define DEBUG   0
#define CHANGE_BIT_SERVICE 0

#define BIT_SET(base, index)    do{(*base) |= (1 << (index));}while(0)
#define BIT_CLEAR(base, index)  do{(*base) &= ~(1 << (index));}while(0)
#define BIT_CHECK(base, index)  (((*base) & (1 << (index))) > 0)

#define GET_ADDR(addr, i, byte)                 ( (uint8_t *) (((uint8_t *)(addr)) + ((i) * (byte))) )

#define __maybe_unused  __attribute__((unused))

typedef enum
{
    FALSE = 0,
    TRUE = 1
}BOOL;

#endif //TYPES_H
