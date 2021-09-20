#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include <time.h>
#include <lamport.h>
#include <types.h>
#include <openssl/aes.h>
#include <gmp.h>
#include <mapping.h>    // combination_mapping array


#define INIT_SODIUM do{ if (sodium_init() < 0) printf("Sodium initialization failed \n\r"); }while(0)

static inline void getNumFromUser(const char *msg, int *num)
{
    printf("%s", msg);
    scanf("%d",num);
}

// TODO optimize, change with table instead of bbit shifting
static inline void changeBitOfByte(ADDR base, const unsigned int byte, const unsigned int bit)
{
    int *number = (int *)(&base[byte]);
    printf("byte %d bit  %d : %d --> ", byte, bit, BIT_CHECK(number, bit));
    if (BIT_CHECK(number, bit)) BIT_CLEAR(number, bit);
    else    BIT_SET(number, bit);
    printf("%d\n\r", BIT_CHECK(number, bit));
}

static void printBytes(const char *msg, ADDR addr, int length)
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

static void changeBitService(int LBit)
{
    int byte, bit;
    if( CHANGE_BIT_SERVICE )
    {
        printBytes("Signature", lamport.signature, lamport.combValues.p * LBit / 8);
        getNumFromUser("Get nth byte for change:", &byte);
        getNumFromUser("Get nth bit for change: ", &bit);
        changeBitOfByte(lamport.signature, byte, bit);    // Change bit
        printBytes("Signature", lamport.signature, lamport.combValues.p * LBit / 8);
    }
}

static msg_node* generateMessages(int t)
{
    int i, random;
    msg_node *messages = NULL;
    char *tmp_msg = NULL;
    time_t time1;

    srand((unsigned) time(&time1)); // Initializes random number generator

    messages =  (msg_node *) calloc(1, sizeof(msg_node) * t);

    for (i = 0; i < t; i++)
    {
        random = (random = (rand() % 512)) > 0 ? random : 1;
        tmp_msg = (char *) malloc(sizeof(char) * random);
        randombytes_buf(tmp_msg, random);
        messages[i].msg = tmp_msg;
        messages[i].msgLen = random;
        if (PRINT) printf("%d -> %d bytes message generated\n", i, random);
        //printBytes("Message is:", messages[i].msg, messages[i].msgLen);
    }

    return messages;
}

static void init_system(int *NBit, int *NByte, int *LBit, int *LByte, int *msgNumber)
{
    getNumFromUser("Length of random numbers (L - bit): ", LBit);
    getNumFromUser("Hash length (N - bit): ", NBit);
    getNumFromUser("Write number of message: (T = 2 ^ n): ", &lamport.numberOfMsg);

    assert(*LBit % 8 == 0 && *LBit != 0); // Length must be 8 ^ n
    *LByte = *LBit / 8;
    assert(*NBit % 8 == 0 && *NBit != 0); // Hash length must be 8 ^ n
    *NByte = *NBit / 8;
    assert(lamport.numberOfMsg > 0); // Number of message must bigger than 0

    lamport.combValues.n = combination_mapping[*NByte - 1][0];
    lamport.combValues.p = combination_mapping[*NByte - 1][1];

    printf("n: %d, p:%d\n", lamport.combValues.n, lamport.combValues.p);

    lamport.messages = generateMessages(lamport.numberOfMsg);  // Generate t message with random length and random bytes

    printf("Write message number to sign(0-%d)\n", lamport.numberOfMsg-1);
    getNumFromUser("Message Number: ", msgNumber);
    assert(*msgNumber < lamport.numberOfMsg && *msgNumber >= 0);

    return;
}

int main(__maybe_unused int argc, __maybe_unused char *argv[])
{
    INIT_SODIUM;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    unsigned char verifyMsgHash[crypto_hash_sha512_BYTES];
    int msgNumber, NBit, NByte, LBit, LByte;
    BOOL isverified;

    init_system(&NBit, &NByte, &LBit, &LByte, &msgNumber);

    // randomly generated and stored IP
    lamport.IP = malloc(BIT_TO_BYTE(LBit) * sizeof(char));
    randombytes_buf(lamport.IP,BIT_TO_BYTE(LBit));

    // Generate pre-images and hash-images
    generateKeysWithIP(LBit, NBit, lamport.combValues.n, lamport.IP, lamport.numberOfMsg);

    crypto_hash_sha512(msgHash512, lamport.messages[msgNumber].msg, lamport.messages[msgNumber].msgLen);    // Calculate hash of message

    lamport.msgHash = malloc(NByte * sizeof(char)); // TODO optimize
    memcpy(lamport.msgHash, msgHash512, NByte);

    signMsg(lamport.msgHash,GET_ADDR(lamport.pre_images, msgNumber, lamport.combValues.n * LByte), LBit, NBit);

    changeBitService(LBit);

    // If you want to change the message, you sould change msg before this method.
    crypto_hash_sha512(verifyMsgHash, lamport.messages[msgNumber].msg, lamport.messages[msgNumber].msgLen);

    if (PRINT)
    {
        printBytes("Sender hash", lamport.msgHash, NByte);
        printBytes("Receiver hash", verifyMsgHash, NByte);
    }

    isverified = verifyMsg(GET_ADDR(lamport.hash_images, msgNumber, lamport.combValues.n * NByte), lamport.signature, verifyMsgHash, LBit, NBit);

    if (isverified)
        printf("Message verified\n");
    else
        printf("Message not verified\n");

    for (int i = 0;i < msgNumber; i++)
        free(lamport.messages[i].msg);

    free(lamport.messages);
    free(lamport.msgHash); free(lamport.signature);
    free(lamport.pre_images); free(lamport.hash_images);

    return 0;
}

