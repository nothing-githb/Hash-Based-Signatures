//
// Created by Halis Şahin on 6.09.2021.
//

#ifndef MCS_MAPPING_H
#define MCS_MAPPING_H

#include <gmp.h>

extern const int combination_mapping[38][2];

void choose(unsigned int n, unsigned int k, mpz_t result);

void get_message_from_mapping(const unsigned int n, const unsigned int p, int *a, mpz_t m);

void get_mapping_from_message(mpz_t m, const unsigned int n, const unsigned int p, int *a);

#endif //MCS_MAPPING_H
