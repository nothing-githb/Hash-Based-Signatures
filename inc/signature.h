//
// Created by Halis Şahin on 19.08.2021.
//

#ifndef MSC_LAMPORT_H
#define MSC_LAMPORT_H

#include <stdint.h>

/************      Client side functions      ************/

uint8_t* init_signature();

uint8_t* sign_msg(uint8_t* msg);

/************      Server side functions      ************/

void server_init_signature(uint8_t * public_values);

int verify_msg(uint8_t* msg, uint8_t* signature);

#endif //MSC_LAMPORT_H
