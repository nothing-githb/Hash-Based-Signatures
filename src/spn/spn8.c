
#include <stdlib.h>
#include <stdio.h>

#include "../Config.h"

#if N_IN == 8

#include <spn/spn8.h>
#include "Spn.h"

void encrypt_bb_8(uint8_t* plain_text, uint8_t* extended_key)
{
    for (int r = 0; r < ROUND; r++)
    {
        if (OUTER_DEBUG) printf("OUTER round %d\n", r);

        /**  nonlinear layer  **/
        nonlinear(plain_text, extended_key);

        /** linear and affine layer **/
        linear_affine(plain_text, r);
    }
}

void encrypt_wb_8(uint8_t* plain_text)
{
    for (int r = 0; r < ROUND; r++)
    {
        if (OUTER_DEBUG) printf("OUTER round %d\n", r);

        /**  nonlinear layer  **/
        nonlinear_wb(plain_text);

        /** linear and affine layer **/
        linear_affine(plain_text, r);
    }
}

#endif

