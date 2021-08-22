//
// Created by Halis Şahin on 19.08.2021.
//

#ifndef MCS_LAMPORT_H
#define MCS_LAMPORT_H

#include <types.h>

extern tLamport lamport;

#define BIT_TO_BYTE(p)  (p/8)
#define BYTE_TO_BIT(p)  (p*8)

#define ADDR_GET_KEY(keys, i, j)        ((keys) + ((i)*TWO*BIT_TO_BYTE(lamport.LBit)) + ((j)*BIT_TO_BYTE(lamport.LBit))
#define ADDR_GET_HASH(hashes, i, j)     ((hashes) + ((i)*TWO*BIT_TO_BYTE(lamport.NBit)) + ((j)*BIT_TO_BYTE(lamport.NBit)))

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

void generateKeys(int length, int totalNumber);

void generateKeysWithIP(int length, int totalNumber, const char *IP);

void signMsg(const unsigned char *msg, const unsigned char *msgHash);

BOOL verifyMsg(const unsigned char *msg, ADDR signature, ADDR hashes, const unsigned char *msgHash);

#endif //MCS_LAMPORT_H
