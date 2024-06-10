//
// Created by Halis Şahin on 19.02.2022.
//

#include <stdio.h>
#include "../Config.h"

#include "Spn.h"
#include "tables/8bit.h"
#include "tables/Tables.h"
#include "../lookup_table/TableMng.h"
#include "../sbox/Sbox.h"

#if N_IN == 8

    /* no inner table */
static const uint8_t outer_table[SIZE_OF_MATRIX][SIZE_OF_MATRIX] = {
        {0x08,0x16,0x8a,0x01,0x70,0x8d,0x24,0x76,0xa8,0x91,0xad,0x48,0x05,0xb5,0xaf,0xf8},
        {0x16,0x08,0x01,0x8a,0x8d,0x70,0x76,0x24,0x91,0xa8,0x48,0xad,0xb5,0x05,0xf8,0xaf},
        {0x8a,0x01,0x08,0x16,0x24,0x76,0x70,0x8d,0xad,0x48,0xa8,0x91,0xaf,0xf8,0x05,0xb5},
        {0x01,0x8a,0x16,0x08,0x76,0x24,0x8d,0x70,0x48,0xad,0x91,0xa8,0xf8,0xaf,0xb5,0x05},
        {0x70,0x8d,0x24,0x76,0x08,0x16,0x8a,0x01,0x05,0xb5,0xaf,0xf8,0xa8,0x91,0xad,0x48},
        {0x8d,0x70,0x76,0x24,0x16,0x08,0x01,0x8a,0xb5,0x05,0xf8,0xaf,0x91,0xa8,0x48,0xad},
        {0xad,0x48,0xa8,0x91,0xaf,0xf8,0x05,0xb5,0x8a,0x01,0x08,0x16,0x24,0x76,0x70,0x8d},
        {0x48,0xad,0x91,0xa8,0xf8,0xaf,0xb5,0x05,0x01,0x8a,0x16,0x08,0x76,0x24,0x8d,0x70},
        {0x05,0xb5,0xaf,0xf8,0xa8,0x91,0xad,0x48,0x70,0x8d,0x24,0x76,0x08,0x16,0x8a,0x01},
        {0xb5,0x05,0xf8,0xaf,0x91,0xa8,0x48,0xad,0x8d,0x70,0x76,0x24,0x16,0x08,0x01,0x8a},
        {0xaf,0xf8,0x05,0xb5,0xad,0x48,0xa8,0x91,0x24,0x76,0x70,0x8d,0x8a,0x01,0x08,0x16},
        {0xf8,0xaf,0xb5,0x05,0x48,0xad,0x91,0xa8,0x76,0x24,0x8d,0x70,0x01,0x8a,0x16,0x08},
        {0x05,0xb5,0xaf,0xf8,0xa8,0x91,0xad,0x48,0x70,0x8d,0x24,0x76,0x08,0x16,0x8a,0x01},
        {0xb5,0x05,0xf8,0xaf,0x91,0xa8,0x48,0xad,0x8d,0x70,0x76,0x24,0x16,0x08,0x01,0x8a},
        {0xad,0x48,0xa8,0x91,0xaf,0xf8,0x05,0xb5,0x8a,0x01,0x08,0x16,0x24,0x76,0x70,0x8d},
        {0x48,0xad,0x91,0xa8,0xf8,0xaf,0xb5,0x05,0x01,0x8a,0x16,0x08,0x76,0x24,0x8d,0x70}};

static const uint8_t* omtrx[SIZE_OF_MATRIX][SIZE_OF_MATRIX] = {
        {TABLE(8, 08),TABLE(8, 16),TABLE(8, 8a),TABLE(8, 01),TABLE(8, 70),TABLE(8, 8d),TABLE(8, 24),TABLE(8, 76),TABLE(8, a8),TABLE(8, 91),TABLE(8, ad),TABLE(8, 48),TABLE(8, 05),TABLE(8, b5),TABLE(8, af),TABLE(8, f8)},
        {TABLE(8, 16),TABLE(8, 08),TABLE(8, 01),TABLE(8, 8a),TABLE(8, 8d),TABLE(8, 70),TABLE(8, 76),TABLE(8, 24),TABLE(8, 91),TABLE(8, a8),TABLE(8, 48),TABLE(8, ad),TABLE(8, b5),TABLE(8, 05),TABLE(8, f8),TABLE(8, af)},
        {TABLE(8, 8a),TABLE(8, 01),TABLE(8, 08),TABLE(8, 16),TABLE(8, 24),TABLE(8, 76),TABLE(8, 70),TABLE(8, 8d),TABLE(8, ad),TABLE(8, 48),TABLE(8, a8),TABLE(8, 91),TABLE(8, af),TABLE(8, f8),TABLE(8, 05),TABLE(8, b5)},
        {TABLE(8, 01),TABLE(8, 8a),TABLE(8, 16),TABLE(8, 08),TABLE(8, 76),TABLE(8, 24),TABLE(8, 8d),TABLE(8, 70),TABLE(8, 48),TABLE(8, ad),TABLE(8, 91),TABLE(8, a8),TABLE(8, f8),TABLE(8, af),TABLE(8, b5),TABLE(8, 05)},
        {TABLE(8, 70),TABLE(8, 8d),TABLE(8, 24),TABLE(8, 76),TABLE(8, 08),TABLE(8, 16),TABLE(8, 8a),TABLE(8, 01),TABLE(8, 05),TABLE(8, b5),TABLE(8, af),TABLE(8, f8),TABLE(8, a8),TABLE(8, 91),TABLE(8, ad),TABLE(8, 48)},
        {TABLE(8, 8d),TABLE(8, 70),TABLE(8, 76),TABLE(8, 24),TABLE(8, 16),TABLE(8, 08),TABLE(8, 01),TABLE(8, 8a),TABLE(8, b5),TABLE(8, 05),TABLE(8, f8),TABLE(8, af),TABLE(8, 91),TABLE(8, a8),TABLE(8, 48),TABLE(8, ad)},
        {TABLE(8, ad),TABLE(8, 48),TABLE(8, a8),TABLE(8, 91),TABLE(8, af),TABLE(8, f8),TABLE(8, 05),TABLE(8, b5),TABLE(8, 8a),TABLE(8, 01),TABLE(8, 08),TABLE(8, 16),TABLE(8, 24),TABLE(8, 76),TABLE(8, 70),TABLE(8, 8d)},
        {TABLE(8, 48),TABLE(8, ad),TABLE(8, 91),TABLE(8, a8),TABLE(8, f8),TABLE(8, af),TABLE(8, b5),TABLE(8, 05),TABLE(8, 01),TABLE(8, 8a),TABLE(8, 16),TABLE(8, 08),TABLE(8, 76),TABLE(8, 24),TABLE(8, 8d),TABLE(8, 70)},
        {TABLE(8, 05),TABLE(8, b5),TABLE(8, af),TABLE(8, f8),TABLE(8, a8),TABLE(8, 91),TABLE(8, ad),TABLE(8, 48),TABLE(8, 70),TABLE(8, 8d),TABLE(8, 24),TABLE(8, 76),TABLE(8, 08),TABLE(8, 16),TABLE(8, 8a),TABLE(8, 01)},
        {TABLE(8, b5),TABLE(8, 05),TABLE(8, f8),TABLE(8, af),TABLE(8, 91),TABLE(8, a8),TABLE(8, 48),TABLE(8, ad),TABLE(8, 8d),TABLE(8, 70),TABLE(8, 76),TABLE(8, 24),TABLE(8, 16),TABLE(8, 08),TABLE(8, 01),TABLE(8, 8a)},
        {TABLE(8, af),TABLE(8, f8),TABLE(8, 05),TABLE(8, b5),TABLE(8, ad),TABLE(8, 48),TABLE(8, a8),TABLE(8, 91),TABLE(8, 24),TABLE(8, 76),TABLE(8, 70),TABLE(8, 8d),TABLE(8, 8a),TABLE(8, 01),TABLE(8, 08),TABLE(8, 16)},
        {TABLE(8, f8),TABLE(8, af),TABLE(8, b5),TABLE(8, 05),TABLE(8, 48),TABLE(8, ad),TABLE(8, 91),TABLE(8, a8),TABLE(8, 76),TABLE(8, 24),TABLE(8, 8d),TABLE(8, 70),TABLE(8, 01),TABLE(8, 8a),TABLE(8, 16),TABLE(8, 08)},
        {TABLE(8, 05),TABLE(8, b5),TABLE(8, af),TABLE(8, f8),TABLE(8, a8),TABLE(8, 91),TABLE(8, ad),TABLE(8, 48),TABLE(8, 70),TABLE(8, 8d),TABLE(8, 24),TABLE(8, 76),TABLE(8, 08),TABLE(8, 16),TABLE(8, 8a),TABLE(8, 01)},
        {TABLE(8, b5),TABLE(8, 05),TABLE(8, f8),TABLE(8, af),TABLE(8, 91),TABLE(8, a8),TABLE(8, 48),TABLE(8, ad),TABLE(8, 8d),TABLE(8, 70),TABLE(8, 76),TABLE(8, 24),TABLE(8, 16),TABLE(8, 08),TABLE(8, 01),TABLE(8, 8a)},
        {TABLE(8, ad),TABLE(8, 48),TABLE(8, a8),TABLE(8, 91),TABLE(8, af),TABLE(8, f8),TABLE(8, 05),TABLE(8, b5),TABLE(8, 8a),TABLE(8, 01),TABLE(8, 08),TABLE(8, 16),TABLE(8, 24),TABLE(8, 76),TABLE(8, 70),TABLE(8, 8d)},
        {TABLE(8, 48),TABLE(8, ad),TABLE(8, 91),TABLE(8, a8),TABLE(8, f8),TABLE(8, af),TABLE(8, b5),TABLE(8, 05),TABLE(8, 01),TABLE(8, 8a),TABLE(8, 16),TABLE(8, 08),TABLE(8, 76),TABLE(8, 24),TABLE(8, 8d),TABLE(8, 70)}};


#elif N_IN == 16


static const uint8_t inner_table[2][2] = {{0x02, 0x01},
                                          {0x03, 0x02}};

static const uint8_t* inner_matrix[2][2] = {{TABLE(8, 02), TABLE(8, 01)},
                                            {TABLE(8, 03), TABLE(8, 02)}};

static const uint16_t outer_table[8][8] = {{0x01,0x03,0x04,0x05,0x06,0x08,0x0b,0x07},
                                           {0x03,0x01,0x05,0x04,0x08,0x06,0x07,0x0b},
                                           {0x04,0x05,0x01,0x03,0x0b,0x07,0x06,0x08},
                                           {0x05,0x04,0x03,0x01,0x07,0x0b,0x08,0x06},
                                           {0x06,0x08,0x0b,0x07,0x01,0x03,0x04,0x05},
                                           {0x08,0x06,0x07,0x0b,0x03,0x01,0x05,0x04},
                                           {0x0b,0x07,0x06,0x08,0x04,0x05,0x01,0x03},
                                           {0x07,0x0b,0x08,0x06,0x05,0x04,0x03,0x01}};

#include "tables/16bit.h"

static const uint16_t* omtrx[SIZE_OF_MATRIX][SIZE_OF_MATRIX] = {
        {TABLE(16, 01), TABLE(16, 03), TABLE(16, 04), TABLE(16, 05), TABLE(16, 06), TABLE(16, 08), TABLE(16, 0b), TABLE(16, 07)},
        {TABLE(16, 03), TABLE(16, 01), TABLE(16, 05), TABLE(16, 04), TABLE(16, 08), TABLE(16, 06), TABLE(16, 07), TABLE(16, 0b)},
        {TABLE(16, 04), TABLE(16, 05), TABLE(16, 01), TABLE(16, 03), TABLE(16, 0b), TABLE(16, 07), TABLE(16, 06), TABLE(16, 08)},
        {TABLE(16, 05), TABLE(16, 04), TABLE(16, 03), TABLE(16, 01), TABLE(16, 07), TABLE(16, 0b), TABLE(16, 08), TABLE(16, 06)},
        {TABLE(16, 06), TABLE(16, 08), TABLE(16, 0b), TABLE(16, 07), TABLE(16, 01), TABLE(16, 03), TABLE(16, 04), TABLE(16, 05)},
        {TABLE(16, 08), TABLE(16, 06), TABLE(16, 07), TABLE(16, 0b), TABLE(16, 03), TABLE(16, 01), TABLE(16, 05), TABLE(16, 04)},
        {TABLE(16, 0b), TABLE(16, 07), TABLE(16, 06), TABLE(16, 08), TABLE(16, 04), TABLE(16, 05), TABLE(16, 01), TABLE(16, 03)},
        {TABLE(16, 07), TABLE(16, 0b), TABLE(16, 08), TABLE(16, 06), TABLE(16, 05), TABLE(16, 04), TABLE(16, 03), TABLE(16, 01)}};

#elif N_IN == 24

static const uint8_t inner_table[3][3] = {{0x02,0x01,0x01},
                                                {0x03,0x01,0x01},
                                                {0x01,0x03,0x02}};

static const uint8_t* inner_matrix[3][3] = {{TABLE(8, 02), TABLE(8, 01), TABLE(8, 01)},
                                                    {TABLE(8, 03), TABLE(8, 02), TABLE(8, 01)},
                                                    {TABLE(8, 01), TABLE(8, 03), TABLE(8, 02)}};

#elif N_IN == 32

static const uint8_t inner_table[4][4] = {{0x02, 0x03, 0x01, 0x01},
                                            {0x01, 0x02, 0x03, 0x01},
                                            {0x01, 0x01, 0x02, 0x03},
                                            {0x03, 0x01, 0x01, 0x01}};

static const const uint8_t* inner_matrix[4][4] = {{TABLE(8, 02), TABLE(8, 03), TABLE(8, 01), TABLE(8, 01)},
                                                {TABLE(8, 01), TABLE(8, 02), TABLE(8, 03), TABLE(8, 01)},
                                                {TABLE(8, 01), TABLE(8, 01), TABLE(8, 02), TABLE(8, 03)},
                                                {TABLE(8, 03), TABLE(8, 01), TABLE(8, 01), TABLE(8, 02)}};

static uint32_t outer_table[4][4] = {{0x01,0x06,0x04,0x02},
                              {0x02,0x01,0x06,0x04},
                              {0x04,0x02,0x01,0x06},
                              {0x06,0x04,0x02,0x01}};

#include "tables/32bit.h"

static const uint32_t* omtrx[SIZE_OF_MATRIX][SIZE_OF_MATRIX] = {
        {TABLE(16, 01), TABLE(16, 06), TABLE(16, 04), TABLE(16, 02)},
        {TABLE(16, 02), TABLE(16, 01), TABLE(16, 06), TABLE(16, 04)},
        {TABLE(16, 04), TABLE(16, 02), TABLE(16, 01), TABLE(16, 06)},
        {TABLE(16, 06), TABLE(16, 04), TABLE(16, 02), TABLE(16, 01)}};
#endif

#if N_IN != 8
static void mix_columns_with_bytes(uint8_t* input)
{
    uint8_t new_values[NUM_OF_BYTES];

    if (MC_DEBUG)
        printf("MC INNER:\n");

    for (int i = 0; i < NUM_OF_BYTES; i++)
    {
        new_values[i] = 0;
        for (int j = 0; j < NUM_OF_BYTES; j++)
        {
            if (MC_DEBUG) printf("%u * %d = %u\n", *(input + j), inner_table[i][j], inner_matrix[i][j][*(input + j)]);
            new_values[i] ^= inner_matrix[i][j][*(input + j)];
        }
    }

    for (int i = 0; i < NUM_OF_BYTES; i++)
    {
        if (MC_DEBUG) printf("%d.: %8u - %8u\n", i, new_values[i], *(input + i));
        *(input + i) = new_values[i];
    }
}
#endif

void small_block_cipher(uint8_t* in, uint8_t* key)
{
    int i = 0, j = 0, key_index = 0;
    for(i = NUM_OF_BYTES-1; i >= 0; i--)
    {
        if (SBC_DEBUG)
            printf("AK %d: %d ^ %d = %d\n", key_index, *(in + i), key[key_index],  AK(*(in + i), key[key_index]));

        *(in + i) = AK(*(in + i), key[key_index]);
        key_index++;
    }

    for(i = 1; i <= NUM_OF_ROUND; i++)
    {
        if (SBC_DEBUG) printf("SBC round : %d\n", i);

        for(j = NUM_OF_BYTES-1; j >= 0; j--)
        {
            if (SBC_DEBUG) printf("SB: %u - %u\n", *(in + j), SB(*(in + j)));
            *(in + j) = SB(*(in + j));
        }

#if N_IN != 8
        mix_columns_with_bytes(in);
#endif

        for(j = NUM_OF_BYTES-1; j >= 0; j--)
        {
            if (SBC_DEBUG) printf("AK %d: %d ^ %d = %d\n", key_index, *(in + j), key[key_index],  AK(*(in + j), key[key_index]));
            *(in + j) = AK(*(in + j), key[key_index]);
            key_index++;
        }
        if (SBC_DEBUG) printf("-----------------------------------\n");
    }

}

#if N_IN != 24

void linear(uint_in* input)
{
    int i = 0, j;
    uint_in tmp_value;
    uint_in new_values[SIZE_OF_MATRIX];

    for (i = 0; i < SIZE_OF_MATRIX; i++)
    {
        tmp_value = 0;
        new_values[i] = 0;
        for (j = 0; j < SIZE_OF_MATRIX; j++)
        {
            tmp_value = (MUL(GET_TABLE(omtrx, i, j, uint_in), *(input + j), uint_in));
            if (MC_DEBUG)
                printf("%u * %d = %u\n", *(input + j), outer_table[i][j], tmp_value);
            new_values[i] ^= tmp_value;
        }

        if (MC_DEBUG)
            printf("matrix[%d] : %u \n", i, new_values[i]);

    }

    for (i = 0; i < SIZE_OF_MATRIX; i++)
    {
        *(input + i) = new_values[i];
        if (MC_DEBUG)
            printf("matrix[%d] : %8u - %8u\n", i, new_values[i], *(input + i));
    }

}

/*******************   nonlinear layer of SPNBOX  ****************************/
void nonlinear(uint_in* input, uint8_t* extended_key)
{
    if (SBC_DEBUG) printf("Small Block Cipher\n\n");

    for(int j = 0; j < T; j++)
        small_block_cipher((uint8_t*)(input + j), extended_key);
}

void nonlinear_wb(uint_in* input)
{
    if (SBC_DEBUG) printf("Small Block Cipher\n\n");

    for(int j = 0; j < T; j++)
        *(input+j) = lookup_table[*(input+j)];
}
/*******************   nonlinear layer of SPNBOX  ****************************/


void linear_affine(uint_in* plain_text, int r)
{
    if (OUTER_DEBUG) printf("Mix Columns Outer\n\n");
    /**  linear layer  **/
    linear(plain_text);

    if (OUTER_DEBUG) printf("Add Round Constant\n\n");

    /**  affine layer  **/
    for(int j = 0; j < T; j++)
    {
        if (OUTER_DEBUG) printf("RC: %d ^ %d = %d\n", *(plain_text+j), r * T + j + 1, *(plain_text+j) ^ (r * T + j + 1));
        *(plain_text+j) ^= r * T + j + 1;
    }
}

#if N_IN == 16 && ENABLE_OPT == 1

#pragma GCC push_options
#pragma GCC optimize ("O0")

#define RC_0  (0x0004000300020001ULL)
#define RC_1  (0x0008000700060005ULL)
#define RC_2  (0x000c000b000a0009ULL)
#define RC_3  (0x0010000f000e000dULL)
#define RC_4  (0x0014001300120011ULL)
#define RC_5  (0x0018001700160015ULL)
#define RC_6  (0x001c001b001a0019ULL)
#define RC_7  (0x0020001f001e001dULL)
#define RC_8  (0x0024002300220021ULL)
#define RC_9  (0x0028002700260025ULL)
#define RC_10 (0x002c002b002a0029ULL)
#define RC_11 (0x0030002f002e002dULL)
#define RC_12 (0x0034003300320031ULL)
#define RC_13 (0x0038003700360035ULL)
#define RC_14 (0x003c003b003a0039ULL)
#define RC_15 (0x0040003f003e003dULL)
#define RC_16 (0x0044004300420041ULL)
#define RC_17 (0x0048004700460045ULL)
#define RC_18 (0x004c004b004a0049ULL)
#define RC_19 (0x0050004f004e004dULL)


//#define MUL_LINE(p) (omtrx[p][0][*x0] ^ omtrx[p][1][*x1] ^ omtrx[p][2][*x2] ^ omtrx[p][3][*x3] ^ omtrx[p][4][*x4] ^ omtrx[p][5][*x5] ^ omtrx[p][6][*x6] ^ omtrx[p][7][*x7])

#define MUL_L0 (*x0 ^ T_16(03)[*x1] ^ T_16(04)[*x2] ^ T_16(05)[*x3] ^ T_16(06)[*x4] ^ T_16(08)[*x5] ^ T_16(0b)[*x6] ^ T_16(07)[*x7])
#define MUL_L1 (T_16(03)[*x0] ^ *x1 ^ T_16(05)[*x2] ^ T_16(04)[*x3] ^ T_16(08)[*x4] ^ T_16(06)[*x5] ^ T_16(07)[*x6] ^ T_16(0b)[*x7])
#define MUL_L2 (T_16(04)[*x0] ^ T_16(05)[*x1] ^ *x2 ^ T_16(03)[*x3] ^ T_16(0b)[*x4] ^ T_16(07)[*x5] ^ T_16(06)[*x6] ^ T_16(08)[*x7])
#define MUL_L3 (T_16(05)[*x0] ^ T_16(04)[*x1] ^ T_16(03)[*x2] ^ *x3 ^ T_16(07)[*x4] ^ T_16(0b)[*x5] ^ T_16(08)[*x6] ^ T_16(06)[*x7])
#define MUL_L4 (T_16(06)[*x0] ^ T_16(08)[*x1] ^ T_16(0b)[*x2] ^ T_16(07)[*x3] ^ *x4 ^ T_16(03)[*x5] ^ T_16(04)[*x6] ^ T_16(05)[*x7])
#define MUL_L5 (T_16(08)[*x0] ^ T_16(06)[*x1] ^ T_16(07)[*x2] ^ T_16(0b)[*x3] ^ T_16(03)[*x4] ^ *x5 ^ T_16(05)[*x6] ^ T_16(04)[*x7])
#define MUL_L6 (T_16(0b)[*x0] ^ T_16(07)[*x1] ^ T_16(06)[*x2] ^ T_16(08)[*x3] ^ T_16(04)[*x4] ^ T_16(05)[*x5] ^ *x6 ^ T_16(03)[*x7])
#define MUL_L7 (T_16(07)[*x0] ^ T_16(0b)[*x1] ^ T_16(08)[*x2] ^ T_16(06)[*x3] ^ T_16(05)[*x4] ^ T_16(04)[*x5] ^ T_16(03)[*x6] ^ *x7)

static uint16_t values[8];
static uint16_t* val_0 = &values[0];
static uint16_t* val_1 = &values[1];
static uint16_t* val_2 = &values[2];
static uint16_t* val_3 = &values[3];
static uint16_t* val_4 = &values[4];
static uint16_t* val_5 = &values[5];
static uint16_t* val_6 = &values[6];
static uint16_t* val_7 = &values[7];

static uint16_t* x0 = NULL;
static uint16_t* x1 = NULL;
static uint16_t* x2 = NULL;
static uint16_t* x3 = NULL;
static uint16_t* x4 = NULL;
static uint16_t* x5 = NULL;
static uint16_t* x6 = NULL;
static uint16_t* x7 = NULL;

void encrypt_wb_16(uint16_t* plain_text)
{
    x0 = plain_text;
    x1 = plain_text+1;
    x2 = plain_text+2;
    x3 = plain_text+3;
    x4 = plain_text+4;
    x5 = plain_text+5;
    x6 = plain_text+6;
    x7 = plain_text+7;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_0;
    *((uint64_t *)x4) ^= RC_1;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_2;
    *((uint64_t *)x4) ^= RC_3;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_4;
    *((uint64_t *)x4) ^= RC_5;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_6;
    *((uint64_t *)x4) ^= RC_7;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_8;
    *((uint64_t *)x4) ^= RC_9;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_10;
    *((uint64_t *)x4) ^= RC_11;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_12;
    *((uint64_t *)x4) ^= RC_13;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_14;
    *((uint64_t *)x4) ^= RC_15;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_16;
    *((uint64_t *)x4) ^= RC_17;

    *x0 = WBT(x0); *x1 = WBT(x1); *x2 = WBT(x2); *x3 = WBT(x3); *x4 = WBT(x4); *x5 = WBT(x5); *x6 = WBT(x6); *x7 = WBT(x7);

    *val_0 = MUL_L0; *val_1 = MUL_L1; *val_2 = MUL_L2; *val_3 = MUL_L3; *val_4 = MUL_L4; *val_5 = MUL_L5; *val_6 = MUL_L6; *val_7 = MUL_L7;

    *((uint64_t *)x0) = *((uint64_t*)val_0);
    *((uint64_t *)x4) = *((uint64_t*)val_4);

    *((uint64_t *)x0) ^= RC_18;
    *((uint64_t *)x4) ^= RC_19;
}


#pragma GCC pop_options

#endif

#endif
