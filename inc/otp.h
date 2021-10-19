//
// Created by Halis Şahin on 10.10.2021.
//

#ifndef MCS_OTP_H
#define MCS_OTP_H


void __otp_fill_mt_leaf_nodes(ADDR mt, ADDR data, const UINT4 NByte);

BOOL verify_otp(ADDR public_key, ADDR otp, ADDR aux, int LBit, int NBit, int mt_height, int index_of_msg);

void generate_totp(ADDR IP, int time_slot, AES_KEY aes_key, int LByte, int day, char *out);

unsigned long calculate_index(time_t initial_time, time_t current_time, int time_slot);

#endif //MCS_OTP_H
