//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <lamport.h>
#include <string.h>
#include <types.h>

#include <openssl/aes.h>

tLamport lamport = {
        .LBit = 0,
        .NBit = 0,
        .keys = NULL,
        .hashes = NULL,
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
/**
 *
 * @param input
 * @param output
 * @param key
 * @param byte
 * @return
 */
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

/**
 *
 * @param length
 * @param totalNumber
 * @param IP
 */
void generateKeysWithIP(int length, int totalNumber, const char *IP)
{
    ADDR addr;
    AES_KEY AESKey;
    int i = 0, j = 0;
    int N = totalNumber / 2;
    int NByte = N / 8, LByte = length / 8;
    unsigned char ip[LByte], out[LByte], key[16];
    unsigned char hash[crypto_hash_sha256_BYTES];

    randombytes_buf(key, 16);   // Generate random key
    AES_set_encrypt_key(&key, 128, &AESKey);    // Set AES encryption key

    memcpy(ip, IP, LByte);  // Copy IP to local ip

    lamport.hashes = malloc(N * TWO * NByte * sizeof(char));    // Allocate memory for hash values(public keys)

    if (PRINT)
    {
        printf("Keys not allocated in memory!!\n");
        printf("sizeof hashes : %d \n", N * TWO * NByte );
    }
    for (i = 0; i < N; i++)
    {
        for (j = 0; j < TWO; j++)
        {
            encryptWithGivenSize(ip, out, &AESKey, LByte);
            crypto_hash_sha256(hash, out, LByte);   // 256 bit hashing
            addr = lamport.hashes + i*TWO*NByte + j*NByte;  // TODO optimize
            memcpy(addr, hash, NByte);
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

/**
 *
 * @param msg
 * @param signature
 * @param hashes
 * @param msgHash
 * @return
 */
BOOL verifyMsg(const unsigned char __maybe_unused *msg, ADDR signature, ADDR hashes, const unsigned char *msgHash)
{
    BOOL isVerified = TRUE;
    ADDR addr1, addr2;
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
            addr1 = ADDR_GET_HASH(hashes, (i * 8) + j ,c & 1);
            addr2 = signature + i * 8 * NByte + j * NByte;
            isVerified = (0 == memcmp(signature + i * 8 * NByte + j * NByte,
                   ADDR_GET_HASH(hashes, (i * 8) + j ,c & 1), NByte));
        }
    }
    return isVerified;
}
