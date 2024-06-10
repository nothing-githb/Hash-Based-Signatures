//
// Created by Halis Şahin on 19.02.2022.
//

#ifndef SPNBOX_SPN_H
#define SPNBOX_SPN_H

#include <stdlib.h>
#include <stdint.h>

#define ROUND                           10

/* p XOR k */
#define AK(p, k)                ((p) ^ (k))


#if N_IN == 8

#define SIZE_OF_MATRIX                  16
#define T                               SIZE_OF_MATRIX
#define NUM_OF_ROUND                    64

typedef uint8_t uint_in;

#elif N_IN == 16

#define SIZE_OF_MATRIX                  8
#define T                               SIZE_OF_MATRIX
#define NUM_OF_ROUND                    32

typedef uint16_t uint_in;

#elif N_IN == 24

#define SIZE_OF_MATRIX                  5
#define T                               SIZE_OF_MATRIX
#define NUM_OF_ROUND                    20

#elif N_IN == 32

#define ROUND                           10
#define SIZE_OF_MATRIX                  4
#define T                               SIZE_OF_MATRIX
#define NUM_OF_ROUND                    16

typedef uint32_t uint_in;

#endif

void small_block_cipher(uint8_t* in, uint8_t* key);

#if N_IN != 24

void linear(uint_in* input);

void nonlinear(uint_in* input, uint8_t* extended_key);

void nonlinear_wb(uint_in* input);

void linear_affine(uint_in* plain_text, int r);

#endif

#endif //SPNBOX_SPN_H
