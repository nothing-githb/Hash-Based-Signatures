//
// Created by Halis Şahin on 21.09.2021.
//

#include <stdio.h>
#include "Helper.h"
#include <signature.h>


inline void increment_bytes(unsigned char *bytes, const int size, const int count)
{
    static mpz_t bytes_to_value;

    // Calculate message hash value
    mpz_init(bytes_to_value);
    mpz_import(bytes_to_value, 1, 1, size, 0, 0, bytes);

    mpz_add_ui(bytes_to_value, bytes_to_value, count);

    mpz_export(bytes, NULL, 1, size, 0, 0, bytes_to_value);

    mpz_clear(bytes_to_value);
}

// TODO optimize, change with table instead of bit shifting
static inline void changeBitOfByte(void* base, const unsigned int byte, const unsigned int bit)
{
    int *number = (int *)(&base[byte]);
    printf("byte %d bit  %d : %d --> ", byte, bit, BIT_CHECK(number, bit));
    if (BIT_CHECK(number, bit)) BIT_CLEAR(number, bit);
    else    BIT_SET(number, bit);
    printf("%d\n\r", BIT_CHECK(number, bit));
}

inline void getNumFromUser(const char *msg, int *num)
{
    printf("%s", msg);
    scanf("%d",num);
}

void printBytes(const char *msg, void* addr, int length)
{
    int i;
    printf("----%s---", msg);
    for (i = 0; i < length; i++)
    {
        if (i % 20 == 0)
            printf("\n");
        printf("%d ", ((unsigned char *)addr)[i]);
    }
    printf("\n\n");
}

void change_bit_service(void* data, int data_byte, const char * msg)
{
    char c;
    int byte, bit;

    printf("Do you want to enable change bit service(y/n):");
    scanf(" %c", &c);

    if ('y' == c || 'Y' == c)
    {
        printBytes(msg, data, data_byte);
        getNumFromUser("Get nth byte for change:", &byte);
        getNumFromUser("Get nth bit for change: ", &bit);
        changeBitOfByte(data, byte, bit);    // Change bit
        printBytes(msg, data, data_byte);
    }
}