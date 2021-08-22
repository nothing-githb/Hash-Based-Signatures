#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include <lamport.h>
#include <types.h>


#define INIT_SODIUM do{                                                     \
    if (sodium_init() < 0) printf("Sodium initialization failed \n\r");     \
    else    printf("Sodium initialized.\n\r");  }while(0)

static inline char * getMessage()
{
    char *msg = NULL;
    char str[256];
    printf("Write message (Max 256) : ");
    scanf("%[^\n]s",str);
    msg = (char *) malloc(strlen(str));
    strncpy(msg, str, strlen(str));
    //printf("%s - %d \n\r",str, strlen(str));
    return msg;
}

static inline int getNumFromUser(const char *msg)
{
    int num;
    printf("%s", msg);
    scanf("%d",&num);
    return num;
}

int main(int argc, char *argv[])
{
    INIT_SODIUM;
    unsigned char msgHash256[crypto_hash_sha256_BYTES];
    ADDR verifyMsgHash;
    BOOL isverified;

    lamport.msg = getMessage();
    lamport.msgLen = strlen(lamport.msg);
    printf("Length: %d - Msg: %s\n\r", lamport.msgLen, lamport.msg);

    lamport.LBit = getNumFromUser("Write length of random numbers (L): ");
    lamport.NBit = (getNumFromUser("Write total number of random numbers (2N): ") / 2);

    printf("Random numbers:\n N: %d , Length: %d bit , %d bytes\n", lamport.NBit, lamport.LBit, lamport.LBit / 8);
    printf("Hashes:\n N: %d , Length: %d bit , %d bytes\n", lamport.NBit, lamport.NBit, lamport.NBit / 8);

    generateKeys(lamport.LBit, lamport.NBit * 2);

    crypto_hash_sha256(msgHash256, lamport.msg, lamport.msgLen);

    lamport.msgHash = malloc(BIT_TO_BYTE(lamport.NBit) * sizeof(char));
    memcpy(lamport.msgHash, msgHash256, BIT_TO_BYTE(lamport.NBit));

    signMsg(lamport.msg, lamport.msgHash);

    printf("%d \n", lamport.msg[0] & 0x02);
    // change first bit 1 to 0
    //lamport.msg[0] = lamport.msg[0] | 0x02;
    printf("%d \n", lamport.msg[0] & 0x02);

    // If you want to change the message, you sould change msg before this method.
    crypto_hash_sha256(msgHash256, lamport.msg, lamport.msgLen);

    verifyMsgHash = malloc(BIT_TO_BYTE(lamport.NBit) * sizeof(char));
    memcpy(verifyMsgHash, msgHash256, BIT_TO_BYTE(lamport.NBit));

    isverified = verifyMsg(lamport.msg, lamport.signature, lamport.hashes, verifyMsgHash);

    if (isverified)
        printf("Message verified\n");
    else
        printf("Message not verified\n");

    free(lamport.msg); free(lamport.msgHash); free(lamport.signature);
    free(lamport.hashes); free(lamport.keys); free(verifyMsgHash);

    return 0;
}

