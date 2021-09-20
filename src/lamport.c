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

static void printBytes(const char *msg, ADDR addr, int length)
{
    int i;
    printf("\n----%s---", msg);
    for (i = 0; i < length; i++)
    {
        if (i % 20 == 0)
            printf("\n");
        printf("%d ", ((unsigned char *)addr)[i]);
    }
    printf("\n\n");
}

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

void generateKeysWithIP(int length, int hashLength, int n, const char *IP, int t)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    int LByte = length / 8, NByte = hashLength / 8;
    unsigned char ip[LByte], out[LByte], key[16];
    AES_KEY AESKey;
    int i, j;

    randombytes_buf(key, 16);   // Generate random key
    AES_set_encrypt_key(&key, 128, &AESKey);    // Set AES encryption key

    memcpy(ip, IP, LByte);  // Copy IP to local ip

    lamport.pre_images = malloc(t * n * LByte * sizeof(char));    // Allocate memory for hash values(public pre_images)
    lamport.hash_images = malloc(t * n * NByte * sizeof(char));    // Allocate memory for hash values(public pre_images)

    for (j = 0; j < t; j++)
    {
        for (i = 0; i < n; i++)
        {
            encryptWithGivenSize(ip, out, &AESKey, LByte);
            memcpy(GET_ADDR(lamport.pre_images, j*n+i, LByte), out, LByte);
            crypto_hash_sha512(msgHash512, out, LByte);
            memcpy(GET_ADDR(lamport.hash_images, j*n+i, NByte), msgHash512, NByte);
            if (DEBUG)
            {
                printf("%d", i);
                printBytes("pre-image", GET_ADDR(lamport.pre_images, i, LByte), LByte);
                printBytes("hash-image", GET_ADDR(lamport.hash_images, i, NByte), NByte);
            }
        }
    }

    return;
}

void signMsg(ADDR msgHash, ADDR pre_images, int LBit, int NBit)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];

    int i, a[lamport.combValues.p];
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;
    // Calculate message hash value
    mpz_init(msgHashValue);
    mpz_import(msgHashValue, 1, LByte, sizeof(char), 0, 0, msgHash);

    lamport.signature = malloc(lamport.combValues.p * LByte * sizeof(char));

    // TODO make malloc function
    if (PRINT) printf("Size of signature : %d bit, %d byte\n", lamport.combValues.p * LBit,
                      lamport.combValues.p * LByte);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    if (PRINT)
    {
        printf("Mapping: ");
        for (int x = 0; x < lamport.combValues.p; x++)
            printf("%d ", a[x]);
        printf("\n");
    }

    for(i = 0; i < lamport.combValues.p; i++)
    {
        memcpy(GET_ADDR(lamport.signature, i, LByte),
               GET_ADDR(pre_images, a[i] - 1, LByte), LByte);
        if (DEBUG)
        {
            crypto_hash_sha512(msgHash512, GET_ADDR(lamport.signature, i, LByte), LByte);
            printBytes("pre-image", GET_ADDR(lamport.signature, i, LByte), LByte);
            printBytes("hash-image", msgHash512, NByte);
        }
    }
    return;
}

BOOL verifyMsg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    BOOL isVerified = TRUE;
    int i = 0, a[lamport.combValues.p];
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;

    // Calculate message hash value
    mpz_init(msgHashValue);
    mpz_import(msgHashValue, 1, NByte, sizeof(char), 0, 0, msgHash);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    if (PRINT)
    {
        printf("Mapping: ");
        for (int x = 0; x < lamport.combValues.p; x++)
            printf("%d ", a[x]);
        printf("\n");
    }

    mpz_clear(msgHashValue);
    for (i = 0; i < lamport.combValues.p && isVerified; i++)
    {
        crypto_hash_sha512(msgHash512, GET_ADDR(signature, i, LByte), LByte);
        isVerified = (0 == memcmp(msgHash512, GET_ADDR(public_key, a[i] - 1, NByte), NByte));
        if ( DEBUG )
        {
            printBytes("pre-image", GET_ADDR(signature, i, LByte), LByte);
            printBytes("hash-image", msgHash512, NByte);
            printBytes("public-key", GET_ADDR(public_key, a[i] - 1, NByte), NByte);
        }
    }

    return isVerified;
}
