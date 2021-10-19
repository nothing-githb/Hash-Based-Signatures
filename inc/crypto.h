//
// Created by Halis Şahin on 11.10.2021.
//

#ifndef MCS_CRYPTO_H
#define MCS_CRYPTO_H

#include <types.h>

void increment_bytes(unsigned char *bytes, const int size, const int count);

void encryptWithGivenSize(unsigned char *input, unsigned char *output, ADDR key, size_t byte);

#endif //MCS_CRYPTO_H
