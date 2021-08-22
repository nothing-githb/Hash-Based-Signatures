//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <lamport.h>
#include <string.h>
#include <types.h>

#define CONTEXT "Examples"

uint8_t master_key[crypto_kdf_KEYBYTES];

uint8_t subkey1[32];
uint8_t subkey2[32];
uint8_t subkey3[64];

tLamport lamport = {
        .LBit = 0,
        .NBit = 0,
        .keys = NULL,
        .hashes = NULL,
        .signature = NULL,
        .msg = NULL,
        .msgLen = 0,
        .msgHash = NULL
};

/**
 *
 * @param[in] length L: the length of random numbers
 * @param[in] totalNumber 2N: total number of random numbers
 * @param[out] keys Generated keys
 * @param[out] hashes
 */
void generateKeys(int length, int totalNumber)
{
    unsigned char out[crypto_hash_sha256_BYTES];
    void *addr;
    void * randNumBuf = malloc(length * sizeof(char));
    int i = 0, j = 0;
    int N = totalNumber / 2;
    int NByte = N / 8;
    int LByte = length / 8;

    lamport.keys = malloc(N * TWO * LByte * sizeof(char));
    lamport.hashes = malloc(N * TWO * NByte * sizeof(char));
    if (PRINT)
    {
        printf("sizeof keys : %d \n", N * TWO * LByte );
        printf("sizeof hashes : %d \n", N * TWO * NByte );
    }
    for (i = 0; i < N; i++)
    {
        for (j = 0; j < TWO; j++)
        {
            randombytes_buf(randNumBuf, LByte);
            addr = lamport.keys + i*TWO*LByte + j*LByte;
            memcpy(addr, randNumBuf, LByte);
            crypto_hash_sha256(out, addr, LByte);
            addr = lamport.hashes + i*TWO*NByte + j*NByte;
            memcpy(addr, out, NByte);
        }
    }
    if (PRINT) printf("Keys generated\n\r");
    free(randNumBuf);
    return;
}

void generateKeysWithIP(int length, int totalNumber, const char *IP)
{
    unsigned char out[crypto_hash_sha256_BYTES];
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char ciphertext[4 + crypto_aead_aes256gcm_ABYTES];
    unsigned long long ciphertext_len;
    ADDR addr;
    int i = 0, j = 0;
    int N = totalNumber / 2;
    int NByte = N / 8, LByte = length / 8;

    crypto_aead_aes256gcm_keygen(key);
    lamport.hashes = malloc(N * TWO * NByte * sizeof(char));
    if (PRINT)
    {
        printf("sizeof keys : %d \n", N * TWO * LByte );
        printf("sizeof hashes : %d \n", N * TWO * NByte );
    }
    for (i = 0; i < N; i++)
    {
        for (j = 0; j < TWO; j++)
        {
            randombytes_buf(nonce, sizeof nonce);
            crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                                          IP, 4,
                                          ADDITIONAL_DATA, ADDITIONAL_DATA_LEN,
                                          NULL, nonce, key);
            addr = lamport.keys + i*TWO*LByte + j*LByte;
            crypto_hash_sha256(out, addr, LByte);
            addr = lamport.hashes + i*TWO*NByte + j*NByte;
            memcpy(addr, out, NByte);
        }
    }
    if (PRINT) printf("Keys generated\n\r");
    return;
}

/**
 *
 * @param msg
 * @param msgHash
 */
void signMsg(const unsigned char *msg, const unsigned char *msgHash)
{
    int i = 0, j = 0;
    unsigned char c;
    int NByte = BIT_TO_BYTE(lamport.NBit);

    lamport.signature = malloc(lamport.NBit * NByte * sizeof(char));
    if (PRINT) printf("sizeof signature : %d \n", lamport.NBit * NByte );

    for (i = 0; i < NByte; i++)
    {
        if (PRINT)
        {
            unsigned char byte = msgHash[i];
            printf("%d\n", byte);
            for(int k = 0; k < 8; k++)
                printf("%d ", (byte >> k) & 0x01);
            printf("\n");
        }
        for (j = 0, c = msgHash[i]; j < 8; j++, c = c >> 1)
        {
            if (PRINT)
            {
                printf("sig: byte: %d \n", i * 8 * NByte + j * NByte);
                printf("hash: i: %d , j: %d\n", (i * 8) + j, c & 1);
            }
            memcpy(lamport.signature + i * 8 * NByte + j * NByte,
                   ADDR_GET_HASH(lamport.hashes, (i * 8) + j ,c & 1), NByte);
        }
    }
}

BOOL verifyMsg(const unsigned char *msg, ADDR signature, ADDR hashes, const unsigned char *msgHash)
{
    BOOL isVerified = TRUE;
    int i = 0, j = 0;
    unsigned char c;
    int NByte = BIT_TO_BYTE(lamport.NBit);


    for (i = 0; i < NByte; i++)
    {
        if (PRINT)
        {
            unsigned char byte = msgHash[i];
            printf("%d\n", byte);
            for(int k = 0; k < 8; k++)
                printf("%d ", (byte >> k) & 0x01);
            printf("\n");
        }
        for (j = 0, c = ((unsigned char *)msgHash)[i]; j < 8 && isVerified; j++, c = c >> 1)
        {
            if (PRINT)
            {
                printf("sig: byte: %d \n", i * 8 * NByte + j * NByte);
                printf("hash: i: %d , j: %d\n", (i * 8) + j, c & 1);
            }
            isVerified = (0 == memcmp(lamport.signature + i * 8 * NByte + j * NByte,
                   ADDR_GET_HASH(lamport.hashes, (i * 8) + j ,c & 1), NByte));
        }
    }
    return isVerified;
}
