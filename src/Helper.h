//
// Created by Halis Şahin on 21.09.2021.
//

#ifndef MCS_HELPER_H
#define MCS_HELPER_H

#include "Types.h"

#define XOR(a,b)                ((a) ^ (b))

/* Concatenate strings */
#define CONCAT(a, b)            (a ## b)

void getNumFromUser(const char *msg, int *num);

void printBytes(const char *msg, void* addr, int length);

void increment_bytes(unsigned char *bytes, const int size, const int count);

void change_bit_service(void* data, int data_byte, const char * msg);

#endif //MCS_HELPER_H
