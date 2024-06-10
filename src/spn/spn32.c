
#include <stdlib.h>
#include <stdio.h>
#include "../Config.h"


#if N_IN == 32

#include <spn/spn32.h>
#include "Spn.h"

void encrypt_bb_32(uint32_t* plain_text, uint8_t* extended_key)
{
    for (int r = 0; r < ROUND; r++)
    {
        if (OUTER_DEBUG) printf("OUTER round %d\n", r);

        /**  nonlinear layer  **/
        nonlinear(plain_text, extended_key);

        /** linear and affine layers **/
        linear_affine(plain_text, r);
    }
}

void encrypt_2b_32(uint32_t* plain_text)
{
    for (int r = 0; r < ROUND; r++)
    {
        if (OUTER_DEBUG) printf("OUTER round %d\n", r);

        /**  nonlinear layer  **/
        nonlinear_wb(plain_text);

        /** linear and affine layers **/
        linear_affine(plain_text, r);
    }
}


#endif

