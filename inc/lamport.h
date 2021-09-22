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

void generate_keys_with_ip(int length, int hash_length, int total_number, const char *IP, int number_of_msg);

void sign_msg(ADDR msg_hash, ADDR pre_images, ADDR hash_images, int LBit, int NBit, ADDR mt, int index_of_msg);

BOOL verify_msg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit, int mt_height, int index_of_msg);

#endif //MSC_LAMPORT_H
