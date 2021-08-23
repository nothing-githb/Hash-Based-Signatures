#ifndef TYPES_H
#define TYPES_H

#define PRINT   0
#define TWO     2

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