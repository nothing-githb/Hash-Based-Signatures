//
// Created by Halis Şahin on 19.02.2022.
//

#ifndef MCS_LAMPORT_H
#define MCS_LAMPORT_H

#include <stdlib.h>

typedef struct{
    void* msg;
    unsigned int msgLen;
}msg_node;

typedef struct{
    void* IP;
    uint32_t increment_value;
}tIP_values;

void generate_keys_with_ip(int total_number,
                           tIP_values* ip_values,
                           int num_of_msg,
                           uint8_t* hash_images);

#endif //MCS_LAMPORT_H
