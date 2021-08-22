#ifndef TYPES_H
#define TYPES_H

#define PRINT   0
#define TWO     2

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
    char *msg;
    int msgLen;
    ADDR msgHash;
    ADDR keys;
    ADDR hashes;
    ADDR signature;
}tLamport;

#endif //TYPES_H