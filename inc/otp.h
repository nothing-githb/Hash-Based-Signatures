//
// Created by Halis Şahin on 19.02.2022.
//

#ifndef MCS_OTP_H
#define MCS_OTP_H

#include <stdint.h>

/************      Client side functions      ************/

uint8_t* init_otp(void);

uint8_t* generate_otp(void);

/************      Server side functions      ************/

void server_init_otp(uint8_t * public_values);

int verify_otp(uint8_t* otp_with_aux);


#endif //MCS_OTP_H
