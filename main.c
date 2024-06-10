#include <stdio.h>
#include <sodium.h>
#include <time.h>
#include <signature.h>
#include "src/Types.h"
#include <gmp.h>
#include "src/mapping/Mapping.h"    // combination_mapping array
#include "src/merkle_tree/Merkle_tree.h"
#include "src/Helper.h"
#include "src/lookup_table/TableMng.h"
#include "src/lamport/Lamport.h"
#include <lookuptable.h>
#include <totp.h>
#include <otp.h>
#include <string.h>
#include "src/Config.h"
#include <spn/spn16.h>
#include <spn/spn8.h>
#include <spn/spn24.h>
#include <arm_neon.h>
#include <unistd.h>

#define INIT_SODIUM do{ if (sodium_init() < 0) printf("Sodium initialization failed \n\r"); }while(0)

#define WB_TEST             1

#define OTP                 0
#define TOTP                1
#define SIGN_MSG            0
#define SPN                 0
#define TEST_COUNT          1


int64_t getAverage(int64_t list[TEST_COUNT])
{
    int64_t sum = 0;
    for(int i = 0; i < TEST_COUNT; i++)
        sum += list[i];

    return sum / TEST_COUNT;
}

uint8_t crypto_spn_encrypt_input_8_test()
{
    uint8_t plain_text[16] = {0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f};
    uint8_t cipher_text[16] = {0x68, 0x99, 0x14, 0x4e, 0x2f, 0xcc, 0x2a, 0xd7, 0x47, 0x99, 0x11, 0xa3, 0x43, 0x9d, 0x22, 0xef};
    get_looktable_fromfile(); // lookuptable8.txt

    printBytes("input",plain_text, 16);
    //encrypt_wb_8(plain_text);
    printBytes("output",plain_text, 16);

    return  memcmp(plain_text, cipher_text, 16);
}

uint8_t crypto_spn_encrypt_input_16_test()
{
    uint8_t plain_text[16] = {0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f};
    uint8_t cipher_text[16] = {0x14, 0x47, 0xc3, 0x5c, 0x75, 0x51, 0x83, 0xfb, 0xce, 0xaf, 0xdc, 0x84, 0x9c, 0xb1, 0x98, 0xf7};
    get_looktable_fromfile(); // lookuptable16.txt

    printBytes("input",plain_text, 16);
    //encrypt_wb_16(plain_text);
    printBytes("output",plain_text, 16);

    return  memcmp(plain_text, cipher_text, 16);
}

uint8_t crypto_spn_encrypt_input_24_test()
{
    uint8_t plain_text[16] = {0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f};
    uint8_t cipher_text[16] = {0x18, 0xfa, 0x30, 0x30, 0xd8, 0x8a, 0x86, 0x52, 0xb0, 0x28, 0x9a, 0x8f, 0x82, 0x8a, 0x4f, 0x6f};
    get_looktable_fromfile(); // lookuptable24.txt
    printBytes("input",plain_text, 16);

    //encrypt_wb_24(plain_text);
    printBytes("output",plain_text, 16);

    return  memcmp(plain_text, cipher_text, 16);
}

extern uint8_t table_generation_spn8_software_test();
extern uint8_t table_generation_spn16_software_test();
extern uint8_t table_generation_spn24_software_test();

int main(__maybe_unused int argc, __maybe_unused char *argv[])
{
    INIT_SODIUM;
    int64_t results[TEST_COUNT];
    int64_t start, end;

    int i = 0;
    BOOL isVerified;

    uint8_t master_key[crypto_kdf_KEYBYTES] = "master_key012345";
    uint8_t* in = malloc(1000000*16);

    randombytes_buf(in, 1000000*16);

    generate_lookuptable((uint8_t*)&master_key);
    get_looktable_fromfile();

    //printf("is verified = %s\n", 0 == crypto_spn_encrypt_input_24_test() ? "Yes" : "No");
    //printf("is verified = %s\n", 0 == table_generation_spn24_software_test() ? "Yes" : "No");

    //while(i++ < TEST_COUNT)
    i=0;
    while(i < TEST_COUNT)
    {

#if SPN == 1

        asm volatile("mrs %0, cntvct_el0" : "=r"(start));
        encrypt_wb_16(in);
        asm volatile("mrs %0, cntvct_el0" : "=r"(end));

        in += 16;
        //printf("%d\n",in);
        //printBytes("in", in, 16);
#elif SIGN_MSG == 1


        uint8_t* root_hash = init_signature();

        server_init_signature(root_hash);

        uint8_t msg[16] = "0123456789012345";

        uint8_t* signature = sign_msg(msg);
        start = clock();

        isVerified = verify_msg(msg, signature);
        end = clock();

        if (isVerified)
            printf("Message verified\n");
        else
            printf("Message not verified\n");

#elif OTP == 1


        uint8_t* root_hash = init_otp();


        server_init_otp(root_hash);


        uint8_t* aux;


        aux = generate_otp();


        start = clock();

        isVerified = verify_otp(aux);
        end = clock();

        if (isVerified)
            printf("OTP verified\n");
        else
            printf("OTP not verified\n");

#elif TOTP == 1

        uint8_t* root_with_init_time = init_totp();

        uint8_t* aux;

        aux = generate_totp();

        server_init_totp(root_with_init_time);

        start = clock();

        sleep(1);
        isVerified = verify_totp(aux);

        end = clock();

        if (isVerified)
            printf("TOTP verified\n");
        else
            printf("TOTP not verified\n");
#endif

        results[i++] = end - start;
        printf("%d --> %lld\n",i, end - start);
    }

    int64_t average = getAverage(results);

    printf("Average cycle --> %lld\n", average);

    return 0;
}

