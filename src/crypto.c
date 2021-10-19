//
// Created by Halis Şahin on 11.10.2021.
//

#include <gmp.h>        /* GNU multiprecision library */
#include <string.h>     /* memcpy */

#include <types.h>
#include <helper.h>

void increment_bytes(unsigned char *bytes, const int size, const int count)
{
    mpz_t bytes_to_value;

    // Calculate message hash value
    mpz_init(bytes_to_value);
    mpz_import(bytes_to_value, 1, 1, size, 0, 0, bytes);

    if (DEBUG)
        gmp_printf("inc: Initial value: %Zd \n", bytes_to_value);

    mpz_add_ui(bytes_to_value, bytes_to_value, count);

    if (DEBUG)
        gmp_printf("inc: Incremented value: %Zd \n", bytes_to_value);

    // mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
    mpz_export(bytes, NULL, 1, size, 0, 0, bytes_to_value);
}

void encryptWithGivenSize(unsigned char *input, unsigned char *output, ADDR key, size_t byte)
{
    unsigned int round = byte >> 4;                 // byte / 16
    const unsigned int remainderBytes = byte & 0xF;    // byte % 16
    int diff = byte - remainderBytes;
    unsigned char remainsIn[16], remainsOut[16];

    while (round > 0)
    {
        AES_encrypt(input, output, key);
        input += 16;
        output += 16;
        round--;
    }
    if (remainderBytes > 0)
    {
        memcpy(remainsIn, input, remainderBytes);  // Copy remainder bytes
        memset(remainsIn + remainderBytes, 0, 16 - remainderBytes);    // Do padding after remainder bytes
        AES_encrypt(remainsIn, remainsOut, key);    // Encrypt
        memcpy(output, remainsOut, remainderBytes);    // Get encrypted
    }
    input -= diff;
    output -= diff;
}