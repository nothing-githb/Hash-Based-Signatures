#include <stdio.h>
#include <string.h>

#include <sodium.h>

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

static inline int getNumFromUser(const char *msg)
{
    int num;
    printf("%s", msg);
    scanf("%d",&num);
    return num;
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
    if( 0 != getNumFromUser("(0) no change \n(1) change\nChange bit service:"))
    {
        byte = getNumFromUser("Get nth byte for change:");
        bit = getNumFromUser("Get nth bit for change: ");
        changeBitOfByte(lamport.msg, byte, bit);    // Change bit
    }
}

int main(__maybe_unused int argc, __maybe_unused char *argv[])
{
    INIT_SODIUM;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    ADDR verifyMsgHash;
    BOOL isverified;

    lamport.msg = getMessage();
    printf("Length: %d - Msg: %s\n\r", lamport.msgLen, lamport.msg);

    lamport.LBit = getNumFromUser("Write length of random numbers (L - bit): ");
    lamport.NBit = getNumFromUser("Write total length of message hash (N - bit): ");
    lamport.combValues.n = combination_mapping[BIT_TO_BYTE(lamport.NBit) - 1][0];
    lamport.combValues.p = combination_mapping[BIT_TO_BYTE(lamport.NBit) - 1][1];

    printf("Random numbers:\n N: %d P: %d, Length: %d bit , %d bytes\n",
           lamport.combValues.n, lamport.combValues.p, lamport.LBit, BIT_TO_BYTE(lamport.LBit));

    mpz_t comb;
    mpz_init(comb);
    choose(lamport.combValues.n, lamport.combValues.p, comb);
    printf("C(%d, %d) = ", lamport.combValues.n, lamport.combValues.p);
    gmp_printf("%20Zd\n", comb);
    mpz_set_ui(comb, 1);
    mpz_ui_pow_ui(comb, 2, lamport.NBit);
    gmp_printf("2 ^ %d = %Zd\n", lamport.NBit, comb);

    // randomly generated and stored IP
    lamport.IP = malloc(BIT_TO_BYTE(lamport.LBit) * sizeof(char));
    randombytes_buf(lamport.IP,BIT_TO_BYTE(lamport.LBit));

    generateKeysWithIP(lamport.LBit, lamport.combValues.n, lamport.IP);     // Generate keys

    crypto_hash_sha256(msgHash512, lamport.msg, lamport.msgLen);    // Calculate hash of message

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
    crypto_hash_sha256(msgHash512, lamport.msg, lamport.msgLen);
    printBytes("hash 2", msgHash512, BIT_TO_BYTE(lamport.NBit));

    verifyMsgHash = malloc(BIT_TO_BYTE(lamport.NBit) * sizeof(char));   // TODO optimize
    memcpy(verifyMsgHash, msgHash512, BIT_TO_BYTE(lamport.NBit));

    isverified = verifyMsg(lamport.msg, lamport.signature, verifyMsgHash);

    if (isverified)
        printf("Message verified\n");
    else
        printf("Message not verified\n");

    free(lamport.msg); free(lamport.msgHash); free(lamport.signature);
    free(lamport.keys); free(verifyMsgHash);
    mpz_clear(lamport.msgHashValue);

    return 0;
}

