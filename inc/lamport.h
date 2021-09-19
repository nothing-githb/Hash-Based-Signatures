//
// Created by Halis Şahin on 19.08.2021.
//

#ifndef MSC_LAMPORT_H
#define MSC_LAMPORT_H

#include <types.h>

extern tLamport lamport;

#define BIT_TO_BYTE(p)  (p/8)
#define BYTE_TO_BIT(p)  (p*8)

#define ADDR_GET_KEY(keys, i)                   ((keys) + (i * BIT_TO_BYTE(lamport.LBit)))
#define ADDR_GET_SIGNATURE(signature, i)        ((signature) + (i * BIT_TO_BYTE(lamport.LBit)))

/**
 *
 * @param length
 * @param totalNumber
 */
void generateKeys(int length, int totalNumber);

/**
 *
 * @param length
 * @param totalNumber
 * @param IP
 */
void generateKeysWithIP(int length, int totalNumber, const char *IP, int numberOfMsg);

/**
 *
 * @param msg
 * @param msgHash
 */

void signMsg(const unsigned char *msg, const unsigned char *msgHash);

/**
 *
 * @param msg
 * @param signature
 * @param hashes
 * @param msgHash
 * @return
 */
BOOL verifyMsg(const unsigned char *msg, ADDR signature, const unsigned char *msgHash);

#endif //MSC_LAMPORT_H
