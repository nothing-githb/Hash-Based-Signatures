//
// Created by Halis Şahin on 21.09.2021.
//

#ifndef MCS_HELPER_H
#define MCS_HELPER_H

#include <types.h>

void getNumFromUser(const char *msg, int *num);

void printBytes(const char *msg, ADDR addr, int length);

void change_bit_service(ADDR data, int data_byte, char * msg);

#endif //MCS_HELPER_H
