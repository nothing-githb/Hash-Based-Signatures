//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <lamport.h>
#include <string.h>
#include <types.h>
#include <merkle_tree.h>
#include <mapping.h>
#include <helper.h>
#include <openssl/aes.h>

tLamport lamport = {
        .combValues.p = 0,
        .combValues.n = 0,
        .signature = NULL,
        .pre_images = NULL,
        .hash_images = NULL,
        .msgHash = NULL,
        .messages = NULL,
        .numberOfMsg = 0,
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

void generate_keys_with_ip(int length, int hash_length, int total_number, const char *IP, int number_of_msg)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    int LByte = length / 8, NByte = hash_length / 8;
    unsigned char ip[LByte], out[LByte], key[16];
    AES_KEY AESKey;
    int i, j;

    randombytes_buf(key, 16);   // Generate random key
    AES_set_encrypt_key(&key, 128, &AESKey);    // Set AES encryption key

    memcpy(ip, IP, LByte);  // Copy IP to local ip

    lamport.pre_images = malloc(number_of_msg * total_number * LByte * sizeof(char));    // Allocate memory for hash values(public pre_images)
    lamport.hash_images = malloc(number_of_msg * total_number * NByte * sizeof(char));    // Allocate memory for hash values(public pre_images)

    for (j = 0; j < number_of_msg; j++)
    {
        for (i = 0; i < total_number; i++)
        {
            encryptWithGivenSize(ip, out, &AESKey, LByte);
            memcpy(GET_ADDR(lamport.pre_images, j * total_number + i, LByte), out, LByte);
            crypto_hash_sha512(msgHash512, out, LByte);
            memcpy(GET_ADDR(lamport.hash_images, j * total_number + i, NByte), msgHash512, NByte);
            if (DEBUG)
            {
                printf("%d", i);
                printBytes("pre-image", GET_ADDR(lamport.pre_images, i, LByte), LByte);
                printBytes("hash-image", GET_ADDR(lamport.hash_images, i, NByte), NByte);
            }
        }
    }

}

void sign_msg(ADDR msg_hash, ADDR pre_images, ADDR hash_images, int LBit, int NBit, ADDR mt, int index_of_msg)
{
    mt_t *merkle_tree = (mt_t *) mt;
    int auxList[merkle_tree->height];
    int i, j, a[lamport.combValues.p];
    ADDR addr;
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;

    // Calculate message hash value
    mpz_init(msgHashValue);
    mpz_import(msgHashValue, 1, LByte, sizeof(char), 0, 0, msg_hash);

    lamport.signature = malloc( (lamport.combValues.p * LByte)
            + ( (lamport.combValues.n - lamport.combValues.p) * NByte )
            + ( merkle_tree->height * NByte + 500)
            );

    if (PRINT) printf("Size of signature : %d bit, %d byte\n", lamport.combValues.p * LBit, lamport.combValues.p * LByte);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    addr = lamport.signature;

    for(i = 0, j = 0; i < lamport.combValues.n; i++)
    {
        if (i >= (a[lamport.combValues.p-1]-1) || i != (a[j] - 1))
        {
            memcpy(addr, GET_ADDR(hash_images, i, NByte), NByte);
            addr += NByte;
        }
        else
        {
            memcpy(addr, GET_ADDR(pre_images, i, LByte), LByte);
            addr += LByte;
            j++;
        }
    }

    getAuxList(index_of_msg, auxList, merkle_tree->height);

    for (i = 0; i < merkle_tree->height; i++)
    {
        memcpy(addr, merkle_tree->nodes[auxList[i]].hash, NByte);
        addr += NByte;
        if (PRINT)
        {
            printf("%d\n", auxList[i]);
            printBytes("node hash", merkle_tree->nodes[auxList[i]].hash, NByte);
        }

    }

}

BOOL verify_msg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit, int mt_height, index_of_msg)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    int auxList[mt_height];
    int i, j, a[lamport.combValues.p];
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;
    ADDR addr;

    // Calculate message hash value
    mpz_init(msgHashValue);
    mpz_import(msgHashValue, 1, NByte, sizeof(char), 0, 0, msgHash);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    mpz_clear(msgHashValue);

    crypto_hash_sha512_init(&state);
    addr = signature;
    for (i = 0, j = 0; i < lamport.combValues.n; i++)
    {
        if (i >= (a[lamport.combValues.p-1]-1) || i != (a[j] - 1))
        {
            crypto_hash_sha512_update(&state, addr, NByte);
            addr += NByte;
        }
        else
        {
            crypto_hash_sha512(msgHash512, addr, LByte);
            crypto_hash_sha512_update(&state, msgHash512, NByte);
            addr += LByte;
            j++;
        }
    }
    crypto_hash_sha512_final(&state, msgHash512);

    getAuxList(index_of_msg, auxList, mt_height);

    for (i = 0;i < mt_height; i++)
    {
        crypto_hash_sha512_init(&state);
        if (0 == (auxList[i] & 1))
        {
            crypto_hash_sha512_update(&state, msgHash512, NByte);
            crypto_hash_sha512_update(&state, addr, NByte);
        }
        else
        {
            crypto_hash_sha512_update(&state, addr, NByte);
            crypto_hash_sha512_update(&state, msgHash512, NByte);
        }
        crypto_hash_sha512_final(&state, msgHash512);
        addr += NByte;
    }

    return (0 == memcmp(msgHash512, public_key, NByte));
}
