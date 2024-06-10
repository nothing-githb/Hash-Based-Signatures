//
// Created by Halis Şahin on 10.10.2021.
//

#ifndef MCS_TOTP_H
#define MCS_TOTP_H

#include <stdint.h>

/************      Client side functions      ************/

uint8_t* init_totp();

uint8_t* generate_totp();

/************      Server side functions      ************/

void server_init_totp(uint8_t * public_values);

int verify_totp(uint8_t* otp_with_aux);


#endif //MCS_TOTP_H
