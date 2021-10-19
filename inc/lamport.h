//
// Created by Halis Şahin on 19.08.2021.
//

#ifndef MSC_LAMPORT_H
#define MSC_LAMPORT_H

#include <types.h>

extern tLamport lamport;

#define BIT_TO_BYTE(p)  (p/8)
#define BYTE_TO_BIT(p)  (p*8)

void generate_keys_with_ip(int len, int hash_len, int total_number, tIP_values ip_values, int num_of_msg, ADDR* pre_images, ADDR* hash_images);

void __lamport_fill_mt_leaf_nodes(ADDR mt, ADDR data, const UINT4 NByte);

void sign_msg(ADDR msg_hash, ADDR pre_images, ADDR hash_images, int LBit, int NBit, ADDR mt, int index_of_msg);

BOOL verify_msg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit, int mt_num_of_leaf_nodes, int index_of_msg);

#endif //MSC_LAMPORT_H
