
#include <stdlib.h>
#include <stdio.h>
#include "../Config.h"

#if N_IN == 24

#include <spn/spn24.h>
#include "tables/24bit.h"
#include "tables/Tables.h"
#include "../sbox/Sbox.h"
#include "../lookup_table/TableMng.h"
#include "Spn.h"

#define BIT24 (0x00ffffff)

static uint32_t outer_table[5][5] = {{0x01,0x04,0x03,0x05,0x02},
                              {0x02,0x01,0x04,0x03,0x05},
                              {0x05,0x02,0x01,0x04,0x03},
                              {0x03,0x05,0x02,0x01,0x04},
                              {0x04,0x03,0x05,0x02,0x01}};

static const uint32_t* omtrx[SIZE_OF_MATRIX][SIZE_OF_MATRIX] = {
        {TABLE(24, 01), TABLE(24, 04), TABLE(24, 03), TABLE(24, 05), TABLE(24, 02)},
        {TABLE(24, 02), TABLE(24, 01), TABLE(24, 04), TABLE(24, 03), TABLE(24, 05)},
        {TABLE(24, 05), TABLE(24, 02), TABLE(24, 01), TABLE(24, 04), TABLE(24, 03)},
        {TABLE(24, 03), TABLE(24, 05), TABLE(24, 02), TABLE(24, 01), TABLE(24, 04)},
        {TABLE(24, 04), TABLE(24, 03), TABLE(24, 05), TABLE(24, 02), TABLE(24, 01)}};

static void linear(uint8_t* input, uint32_t*  matrix[SIZE_OF_MATRIX][SIZE_OF_MATRIX])
{
    int i = 0, j;
    uint32_t tmp_value;
    uint32_t new_values[SIZE_OF_MATRIX];

    for (i = 0; i < SIZE_OF_MATRIX; i++)
    {
        tmp_value = 0;
        new_values[i] = 0;
        for (j = 0; j < SIZE_OF_MATRIX; j++)
        {
            tmp_value = (MUL(GET_TABLE(matrix, i, j, uint32_t), ((*(input + j * 3)) | ((*(input + j * 3 + 1)) << 8) | ((*(input + j * 3 + 2)) << 16) ), uint32_t));
            if (MC_DEBUG)
                printf("%u * %d = %u\n", ((*(input + j * 3)) | ((*(input + j * 3 + 1)) << 8) | ((*(input + j * 3 + 2)) << 16) ), outer_table[i][j], tmp_value);
            new_values[i] ^= (BIT24 & (tmp_value));
        }

        if (MC_DEBUG)
            printf("matrix[%d] : %u \n", i, new_values[i]);

    }

    for (i = 0; i < SIZE_OF_MATRIX; i++)
    {
        if (MC_DEBUG)
            printf("matrix[%d] : %8u - %8u\n", i, new_values[i], *(input + i * 3) | *(input + i * 3 +1 ) << 8 | *(input + i * 3 + 2) << 16 );
        *(input + i * 3)     = (uint8_t) ( new_values[i] & 0x000000ff);
        *(input + i * 3 + 1) = (uint8_t) ((new_values[i] & 0x0000ff00) >> 8);
        *(input + i * 3 + 2) = (uint8_t) ((new_values[i] & 0x00ff0000) >> 16);
    }

}

/*******************   (inv)nonlinear layer of SPNBOX24  **********************/
static void nonlinear(uint8_t* input, uint8_t* extended_key)
{
    if (SBC_DEBUG) printf("Small Block Cipher\n\n");

    for(int j = 0; j < T; j++)
        small_block_cipher(input+j*3, extended_key);
}

static void nonlinear_wb(uint8_t* input)
{
    int temp = 0;
    if (SBC_DEBUG) printf("Small Block Cipher\n\n");

    for(int j = 0; j < T; j++)
    {
        temp = (*(input+j*3)) | ((*(input+j*3+1)) << 8) | ((*(input+j*3+2)) << 8);
        temp = lookup_table[temp];
        *(input+j*3)   = (uint8_t) (temp & 0x000000ff);
        *(input+j*3+1) = (uint8_t) ((temp & 0x0000ff00) >> 8);
        *(input+j*3+2) = (uint8_t) ((temp & 0x00ff0000) >> 16);
    }
}
/*******************     nonlinear layer of SPNBOX24     **********************/

static inline void linear_affine(uint8_t* plain_text, int r)
{
    int rc = 0;

    if (OUTER_DEBUG) printf("Mix Columns Outer\n\n");

    /**  linear layer  **/
    linear(plain_text, omtrx);

    if (OUTER_DEBUG) printf("Add Round Constant\n\n");

    /**  affine layer  **/
    for(int j = 0; j < T; j++)
    {
        rc = r * T + j + 1;
        if (OUTER_DEBUG) printf("RC: %d ^ %d = %d\n", *(plain_text+j*3), rc, *(plain_text+j*3) ^ (r * T + j + 1));
        *(plain_text+j*3)   ^= (uint8_t) (rc & 0x000000ff);
        *(plain_text+j*3+1) ^= (uint8_t) ((rc & 0x0000ff00) >> 8);
        *(plain_text+j*3+2) ^= (uint8_t) ((rc & 0x00ff0000) >> 16);
    }
}


void encrypt_bb_24(uint8_t* plain_text, uint8_t* extended_key)
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

void encrypt_wb_24(uint8_t* plain_text)
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

