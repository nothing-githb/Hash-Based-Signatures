#ifndef TYPES_H
#define TYPES_H

#define PRINT   0
#define TWO     2

#define BIT_SET(base, index)    do{(*base) |= (1 << (index));}while(0)
#define BIT_CLEAR(base, index)  do{(*base) &= ~(1 << (index));}while(0)
#define BIT_CHECK(base, index)  (((*base) & (1 << (index))) > 0)

#define __maybe_unused  __attribute__((unused))

typedef void * ADDR;

typedef enum
{
    FALSE = 0,
    TRUE = 1
}BOOL;

typedef struct
{
    int LBit;
    int NBit;
    unsigned char *msg;
    int msgLen;
    ADDR msgHash;
    ADDR IP;
    ADDR keys;
    ADDR hashes;
    ADDR signature;
}tLamport;

#endif //TYPES_H
