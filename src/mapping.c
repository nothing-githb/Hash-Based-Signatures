//
// Created by Halis Şahin on 6.09.2021.
//

#include <gmp.h>
#include <mapping.h>

const unsigned int combination_mapping[38][2] ={
        // n    p           bit
        { 11,   4},  //   8 bit
        { 19,   8},  //  16 bit
        { 27,  12},  //  24 bit
        { 35,  17},  //  32 bit
        { 44,  19},  //  40 bit
        { 52,  23},  //  48 bit
        { 60,  27},  //  56 bit
        { 68,  31},  //  64 bit
        { 76,  35},  //  72 bit
        { 84,  39},  //  80 bit
        { 92,  43},  //  88 bit
        {100,  47},  //  96 bit
        {108,  51},  // 104 bit
        {116,  55},  // 112 bit
        {124,  60},  // 120 bit
        {132,  64},  // 128 bit
        {140,  68},  // 136 bit
        {148,  73},  // 144 bit
        {156,  77},  // 152 bit
        {165,  75},  // 160 bit
        {173,  79},  // 168 bit
        {181,  83},  // 176 bit
        {189,  87},  // 184 bit
        {197,  91},  // 192 bit
        {205,  95},  // 200 bit
        {213,  99},  // 208 bit
        {221, 103},  // 216 bit
        {229, 107},  // 224 bit
        {237, 111},  // 232 bit
        {245, 115},  // 240 bit
        {253, 119},  // 248 bit
        {261, 123},  // 256 bit
        {269, 127},  // 264 bit
        {277, 131},  // 272 bit
        {285, 135},  // 280 bit
      //  {517, 254},  // 512 bit
      //  {1030, 500},  // 1024 bit
};

void choose(unsigned int n, unsigned int k, mpz_t result)
{
    unsigned int i;
    if (k > n)
        return;
    mpz_set_ui(result, 1);
    for (i = 1; i <= k; i++)
    {
        //result *= n--;
        mpz_mul_ui(result, result, n);
        n--;
        //result /= i;
        mpz_div_ui(result, result, i);
    }
}

void get_message_from_mapping(const unsigned int n, const unsigned int p, int *a, mpz_t m)
{
    mpz_t comb;
    mpz_init(comb);
    unsigned int i, j;
    for (i = 1; i <= p; i++)
    {
        for (j = (n - a[i] + 1); j <= (n - a[i-1] -1); j++) // TODO optimize
        {
            choose(j, p - i, comb);
            mpz_add(m, m, comb);
        }
    }
    mpz_add_ui(m, m, 1);
    mpz_clear(comb);    // free used memory
}

void get_mapping_from_message(mpz_t m, const unsigned int n, const unsigned int p, int *a)
{
    unsigned int i, q = 1;
    mpz_t comb;
    mpz_init(comb);
    for(i = 1; i <= p; i++)
    {
        choose(n - q, p - i, comb);
        while (mpz_cmp(m, comb) > 0)
        {
            //m -= comb;
            mpz_sub(m, m, comb);
            q++;
            choose(n - q, p - i, comb);
        }
        a[i-1] = q;
        q++;
    }
    mpz_clear(comb); // free used memory
}
