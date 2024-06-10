//
// Created by Halis Şahin on 27.01.2022.
//

#include <gmp.h>        /* GNU multiprecision library */
#include "../Config.h"
#include <string.h>     /* memset */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include "../Helper.h"
#include "TableMng.h"
#include <lookuptable.h>

#include "../spn/Spn.h"


#if 8 == N_IN
#define SIZE_OF_KEY                     65
typedef uint8_t uint_in_t;
static const char* filename = "lookuptable8.txt";
#elif 16 == N_IN
#define SIZE_OF_KEY                     66
typedef uint16_t uint_in_t;
static const char* filename = "lookuptable16.txt";
#elif 24 == N_IN
#define SIZE_OF_KEY                     63
typedef uint32_t uint_in_t;
static const char* filename = "lookuptable24.txt";
#elif 32 == N_IN
#define SIZE_OF_KEY                     68
typedef uint32_t uint_in_t;
static const char* filename = "lookuptable32.txt";
#endif

uint_in_t lookup_table[1<<N_IN];

void get_looktable_fromfile()
{
    int i = 0;

    FILE* file = fopen(filename, "rb");

    if (!file)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while(i < (1<<N_IN))
    {
        fread(&lookup_table[i], NUM_OF_BYTES, 1, file);
        i++;
    }

    fclose(file);
}

#define CONTEXT "Examples"

void key_schedule(uint8_t* key, uint8_t* output)
{
    uint8_t local_key[crypto_kdf_KEYBYTES];

    uint8_t subkey[SIZE_OF_KEY];
#if N_IN != 24
    uint8_t subkey1[16];
#endif

    memset(local_key, 0x0, crypto_kdf_KEYBYTES);
    memcpy(local_key, key, 16);

    memset(subkey, 0x0, SIZE_OF_KEY);

#if N_IN != 24
    crypto_kdf_derive_from_key(subkey, 64, 1, CONTEXT, local_key);
    crypto_kdf_derive_from_key(subkey1, sizeof(subkey1), NUM_OF_BYTES, CONTEXT, local_key);
    memcpy(subkey+64, subkey1, NUM_OF_BYTES);
#else
    crypto_kdf_derive_from_key(subkey, 63, 1, CONTEXT, local_key);
#endif

    if (KC_DEBUG)
        printBytes("last key", subkey, SIZE_OF_KEY);

    memcpy(output, subkey, SIZE_OF_KEY);
}

void generate_lookuptable(uint8_t* master_key)
{
    uint64_t i = 0;
    uint8_t  input[NUM_OF_BYTES];
    uint8_t  output[NUM_OF_BYTES];

    uint8_t extended_key[SIZE_OF_KEY] = "01234567861123456789012345678901234567890123456789012345678901234";
    FILE*    output_file = NULL;

    memset(input, 0x00, NUM_OF_BYTES);
    memset(output, 0x00, NUM_OF_BYTES);

    //key_schedule(master_key, &extended_key);

    output_file = fopen(filename, "wb+");

    if (!output_file)
    {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    while(i++ < (1<<N_IN))
    {
        small_block_cipher(input, extended_key);

        fwrite(input, NUM_OF_BYTES, 1, output_file);
        increment_bytes(output, NUM_OF_BYTES, 1);
        memcpy(input, output, NUM_OF_BYTES);
    }

    fclose(output_file);
}

uint8_t table_generation_spn8_software_test()
{
    FILE *file;
    int isVerified;
    int i = 0;
    uint8_t* test_table = malloc((1<<N_IN) * sizeof(uint8_t));
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    generate_lookuptable(key);
    get_looktable_fromfile(); // Global lookup_table dizisi dolduruldu.

    file = fopen("test_lookuptable8.txt", "rb");

    fread(test_table, NUM_OF_BYTES, (1<<N_IN), file);

    isVerified = memcmp(test_table, lookup_table, (1<<N_IN) * sizeof(uint8_t));

    free(test_table);
    fclose(file);

    return isVerified;
}

uint8_t table_generation_spn16_software_test()
{
    FILE *file;
    int isVerified;
    int i = 0;
    uint16_t* test_table = malloc((1<<N_IN) * sizeof(uint16_t));
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    generate_lookuptable(key);
    get_looktable_fromfile(); // Global lookup_table dizisi dolduruldu.

    file = fopen("test_lookuptable16.txt", "rb");

    fread(test_table, NUM_OF_BYTES, (1<<N_IN), file);

    isVerified = memcmp(test_table, lookup_table, (1<<N_IN) * sizeof(uint16_t));

    free(test_table);
    fclose(file);

    return isVerified;
}

uint8_t table_generation_spn24_software_test()
{
    FILE *file;
    int isVerified = 0;
    int i = 0;
    uint32_t* test_table = malloc((1<<N_IN) * sizeof(uint32_t));
    memset(test_table, 0x0, (1<<N_IN) * sizeof(uint32_t));
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    generate_lookuptable(key);
    get_looktable_fromfile(); // Global lookup_table dizisi dolduruldu.

    file = fopen("test_lookuptable24.txt", "rb");

    while(i < (1<<N_IN))
    {
        fread(&test_table[i], NUM_OF_BYTES, 1, file);
        i++;
    }

    i = 0;

    while(isVerified == 0 && i < (1<<N_IN))
    {
        isVerified = memcmp(&test_table[i], &lookup_table[i], 3);
        i++;
    }

    free(test_table);
    fclose(file);

    return isVerified;
}
