//
// Created by Halis Şahin on 19.08.2021.
//

#ifndef MSC_LAMPORT_H
#define MSC_LAMPORT_H

#include <types.h>

extern tLamport lamport;

#define BIT_TO_BYTE(p)  (p/8)
#define BYTE_TO_BIT(p)  (p*8)

#define GET_ADDR(addr, i, byte)                 ( (ADDR) (((char *)addr) + ((i) * (byte))) )

void generateKeysWithIP(int length, int hashLength, int totalNumber, const char *IP, int numberOfMsg);

void signMsg(ADDR msgHash, ADDR pre_images, int LBit, int NBit);

BOOL verifyMsg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit);

#endif //MSC_LAMPORT_H
