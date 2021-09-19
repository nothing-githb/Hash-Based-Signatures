//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <lamport.h>
#include <string.h>
#include <types.h>

#include <mapping.h>

#include <openssl/aes.h>

tLamport lamport = {
        .LBit = 0,
        .NBit = 0,
        .combValues.n = 0,
        .combValues.p = 0,
        .pre_images = NULL,
        .hash_images = NULL,
        .signature = NULL,
        .msg = NULL,
        .msgLen = 0,
        .msgHash = NULL,
        .IP = NULL
};

static inline void incrementOne(unsigned char *bytes, int size)
{
    int i;
    for (i = size-1; i >= 0; i--)
    {
        if (0 == ++bytes[i]) continue;
        else break;
    }
}

static inline void encryptWithGivenSize(unsigned char *input, unsigned char *output, ADDR key, size_t byte)
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
    incrementOne(input, byte);
}

void generateKeysWithIP(int length, int n, const char *IP, int t)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    AES_KEY AESKey;
    int i, j;
    int LByte = length / 8;
    unsigned char ip[LByte], out[LByte], key[16];

    randombytes_buf(key, 16);   // Generate random key
    AES_set_encrypt_key(&key, 128, &AESKey);    // Set AES encryption key

    memcpy(ip, IP, LByte);  // Copy IP to local ip

    lamport.pre_images = malloc(t * n * LByte * sizeof(char));    // Allocate memory for hash values(public pre_images)
    lamport.hash_images = malloc(t * n * LByte * sizeof(char));    // Allocate memory for hash values(public pre_images)

    for (j = 0; j < t; j++)
    {
        for (i = 0; i < n; i++)
        {
            encryptWithGivenSize(ip, out, &AESKey, LByte);
            memcpy(ADDR_GET_KEY(lamport.pre_images, (j * n + i)), out, LByte);

        }
    }

    return;
}

void signMsg(const unsigned char *msg, const unsigned char *msgHash)
{
    int i, a[lamport.combValues.p];
    int LByte = BIT_TO_BYTE(lamport.LBit);

    // Calculate message hash value
    mpz_init(lamport.msgHashValue);
    mpz_import (lamport.msgHashValue, 1, BIT_TO_BYTE(lamport.NBit), sizeof(char), 0, 0, msgHash);

    lamport.signature = malloc(lamport.combValues.p * LByte * sizeof(char));

    // TODO make malloc function
    if (PRINT) printf("Size of signature : %d bit, %d byte\n", lamport.combValues.p * lamport.LBit,
                      lamport.combValues.p * LByte);

    get_mapping_from_message(lamport.msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    for(i = 0; i < lamport.combValues.p; i++)
        memcpy(ADDR_GET_SIGNATURE(lamport.signature, i),
               ADDR_GET_KEY(lamport.pre_images, a[i] - 1), LByte);
}

BOOL verifyMsg(const unsigned char __maybe_unused *msg, ADDR signature, const unsigned char *msgHash)
{
    BOOL isVerified = TRUE;
    int i = 0, a[lamport.combValues.p];
    int NByte = BIT_TO_BYTE(lamport.NBit);
    mpz_t msgHashValue;

    // Calculate message hash value
    mpz_init(msgHashValue);
    mpz_import(msgHashValue, 1, NByte, sizeof(char), 0, 0, msgHash);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    mpz_clear(msgHashValue);
    for (i = 0; i < lamport.combValues.p && isVerified; i++)
    {
            isVerified = (0 == memcmp(ADDR_GET_SIGNATURE(signature, i),
                                      ADDR_GET_KEY(lamport.pre_images, a[i] - 1), NByte));
    }

    return isVerified;
}
