//
// Created by Halis Şahin on 21.09.2021.
//

#include <stdio.h>
#include <helper.h>
#include <lamport.h>

// TODO optimize, change with table instead of bit shifting
static inline void changeBitOfByte(ADDR base, const unsigned int byte, const unsigned int bit)
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

void printBytes(const char *msg, ADDR addr, int length)
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

void change_bit_service(ADDR data, int data_byte, char * msg)
{
    int byte, bit;
    printBytes(msg, data, data_byte);
    getNumFromUser("Get nth byte for change:", &byte);
    getNumFromUser("Get nth bit for change: ", &bit);
    changeBitOfByte(data, byte, bit);    // Change bit
    printBytes(msg, data, data_byte);
}