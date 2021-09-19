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


#define INIT_SODIUM do{                                                     \
    if (sodium_init() < 0) printf("Sodium initialization failed \n\r");     \
    else    printf("Sodium initialized.\n\r");  }while(0)

static inline unsigned char * getMessage()
{
    unsigned char *msg = NULL;
    char str[1024];
    printf("Write message (Max 1024) : ");
    scanf("%[^\n]s",str);
    lamport.msgLen = strlen(((const char *)str));
    msg = (unsigned char *) malloc(lamport.msgLen * sizeof(char));
    memcpy(msg, str, lamport.msgLen);
    return msg;
}

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

static void printBytes(char *msg, ADDR addr, int length)
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

static void changeBitService()
{
    int byte, bit;
    if( CHANGE_BIT_SERVICE )
    {
        getNumFromUser("Get nth byte for change:", &byte);
        getNumFromUser("Get nth bit for change: ", &bit);
        changeBitOfByte(lamport.msg, byte, bit);    // Change bit
    }
}

static msg_node* generateMessages(int t)
{
    int i, random;
    msg_node *messages = NULL;
    msg_node *tmp_node = NULL;
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
        printf("%d bytes message generated\n", random);
        printBytes("Message is:", messages[i].msg, messages[i].msgLen);
    }

    return messages;
}

int main(__maybe_unused int argc, __maybe_unused char *argv[])
{
    INIT_SODIUM;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    ADDR verifyMsgHash;
    BOOL isverified;

    getNumFromUser("Length of random numbers (L - bit): ", &lamport.LBit);
    getNumFromUser("Hash length (N - bit): ", &lamport.NBit);
    getNumFromUser("Write number of message: (T = 2 ^ n): ", &lamport.numberOfMsg);

    assert(lamport.LBit % 8 == 0); // Length must be 8 ^ n
    assert(lamport.NBit % 8 == 0); // Hash length must be 8 ^ n
    assert(lamport.numberOfMsg % 8 == 0); // Number of message must be 2 ^ n

    generateMessages(lamport.numberOfMsg);  // Generate t message with random length and random bytes

    lamport.combValues.n = combination_mapping[BIT_TO_BYTE(lamport.NBit) - 1][0];
    lamport.combValues.p = combination_mapping[BIT_TO_BYTE(lamport.NBit) - 1][1];

    // randomly generated and stored IP
    lamport.IP = malloc(BIT_TO_BYTE(lamport.LBit) * sizeof(char));
    randombytes_buf(lamport.IP,BIT_TO_BYTE(lamport.LBit));

    /**
     * Generate pre-images and hash-images
     */
    generateKeysWithIP(lamport.LBit, lamport.combValues.n, lamport.IP, lamport.numberOfMsg);

    crypto_hash_sha512(msgHash512, lamport.msg, lamport.msgLen);    // Calculate hash of message

    lamport.msgHash = malloc(BIT_TO_BYTE(lamport.NBit) * sizeof(char)); // TODO optimize
    memcpy(lamport.msgHash, msgHash512, BIT_TO_BYTE(lamport.NBit));

    signMsg(lamport.msg, lamport.msgHash);

    printBytes("msg\n", lamport.msg, strlen(lamport.msg));
    changeBitService();
    printBytes("msg\n", lamport.msg, strlen(lamport.msg));

//    printBytes("Signature\n----------\n", lamport.signature, lamport.combValues.p * lamport.LBit / 8);
//    changeBitService();
//    printBytes("Signature\n----------\n", lamport.signature, lamport.combValues.p * lamport.LBit / 8);

    printBytes("hash 1", msgHash512, BIT_TO_BYTE(lamport.NBit));
    // If you want to change the message, you sould change msg before this method.
    crypto_hash_sha512(msgHash512, lamport.msg, lamport.msgLen);
    printBytes("hash 2", msgHash512, BIT_TO_BYTE(lamport.NBit));

    verifyMsgHash = malloc(BIT_TO_BYTE(lamport.NBit) * sizeof(char));   // TODO optimize
    memcpy(verifyMsgHash, msgHash512, BIT_TO_BYTE(lamport.NBit));

    isverified = verifyMsg(lamport.msg, lamport.signature, verifyMsgHash);

    if (isverified)
        printf("Message verified\n");
    else
        printf("Message not verified\n");

    free(lamport.msg); free(lamport.msgHash); free(lamport.signature);
    free(lamport.pre_images); free(verifyMsgHash);
    mpz_clear(lamport.msgHashValue);

    return 0;
}

