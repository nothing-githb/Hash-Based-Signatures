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
#include <merkle_tree.h>
#include <helper.h>
#include <otp.h>

#define INIT_SODIUM do{ if (sodium_init() < 0) printf("Sodium initialization failed \n\r"); }while(0)


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
    getNumFromUser("Write number of leaf node: (T = 2 ^ n): ", &lamport.numberOfMsg);

    assert(*LBit % 8 == 0 && *LBit != 0); // Length must be 8 ^ n
    *LByte = *LBit / 8;
    assert(*NBit % 8 == 0 && *NBit != 0); // Hash length must be 8 ^ n
    *NByte = *NBit / 8;
    assert(lamport.numberOfMsg > 0); // Number of message must bigger than 0

    // Get n and p values from mapping array.
    lamport.combValues.n = combination_mapping[*NByte - 1][0];
    lamport.combValues.p = combination_mapping[*NByte - 1][1];

    printf("n: %d, p:%d\n", lamport.combValues.n, lamport.combValues.p);

    //lamport.messages = generateMessages(lamport.numberOfMsg);  // Generate t message with random length and random bytes

    // Get index of message to sign
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
    int msgNumber, NBit = 0, NByte = 0, LBit = 0, LByte = 0;
    mt_t *mt = NULL;
    ADDR pre_images = NULL;
    ADDR hash_images = NULL;
    BOOL isVerified;
    ADDR aux;

    init_system(&NBit, &NByte, &LBit, &LByte, &msgNumber);

    // randomly generated and stored IP
    lamport.ip_values.IP = malloc(BIT_TO_BYTE(LBit) * sizeof(char));
    randombytes_buf(lamport.ip_values.IP,BIT_TO_BYTE(LBit));

    /**
    lamport.ip_values.increment_value = 1;

    // Generate pre-images and hash-images
    generate_keys_with_ip(LBit, NBit, lamport.combValues.n, lamport.ip_values, lamport.numberOfMsg, &lamport.pre_images, &lamport.hash_images);

    // Initialize merkle tree and fill leaf nodes
    mt = init_mt(lamport.hash_images, lamport.numberOfMsg, NByte, (ADDR)__lamport_fill_mt_leaf_nodes);

    // Build root and internal nodes
    build_mt(mt, NByte);

    // Calculate hash of message
    crypto_hash_sha512(msgHash512, lamport.messages[msgNumber].msg, lamport.messages[msgNumber].msgLen);

    lamport.msgHash = malloc(NByte * sizeof(char)); // TODO optimize
    memcpy(lamport.msgHash, msgHash512, NByte);

    pre_images = GET_ADDR(lamport.pre_images, msgNumber, lamport.combValues.n * LByte);
    hash_images = GET_ADDR(lamport.hash_images, msgNumber, lamport.combValues.n * NByte);

    sign_msg(lamport.msgHash, pre_images, hash_images, LBit, NBit, mt, msgNumber);


    // If you want to change the message, you sould change msg before this method.
    crypto_hash_sha512(verifyMsgHash, lamport.messages[msgNumber].msg, lamport.messages[msgNumber].msgLen);

    //change_bit_service(lamport.signature, (lamport.combValues.p * LByte)+ ( (lamport.combValues.n - lamport.combValues.p) * NByte )+ ( mt->height * NByte ), "signature");

    if (PRINT)
    {
        printBytes("Sender hash", lamport.msgHash, NByte);
        printBytes("Receiver hash", verifyMsgHash, NByte);
    }

    // Root hash
    printBytes("root hash",GET_ROOT_HASH(mt), NByte);

    isVerified = verify_msg(GET_ROOT_HASH(mt), lamport.signature, verifyMsgHash, LBit, NBit, mt->num_of_leaf_nodes, msgNumber);

    if (isVerified)
        printf("Message verified\n");
    else
        printf("Message not verified\n");

    for (int i = 0;i < msgNumber; i++)
        free(lamport.messages[i].msg);

    free(lamport.messages);
    free(lamport.msgHash); free(lamport.signature);
    free(lamport.pre_images); free(lamport.hash_images);


    */

    /**
    lamport.ip_values.increment_value = 1;

    generate_keys_with_ip(LBit, NBit, lamport.numberOfMsg, lamport.ip_values, 1, &lamport.pre_images, &lamport.hash_images);

    mt = init_mt(lamport.hash_images, lamport.numberOfMsg, NByte, __otp_fill_mt_leaf_nodes);

    // Generate root hash, public key
    build_mt(mt, NByte);

    aux = malloc(mt->height * NByte *sizeof(char));

    mt_generate_aux(mt, msgNumber, NByte, aux);

    //change_bit_service(aux, mt->height * NByte, "aux");

    isVerified = verify_otp(GET_ROOT_HASH(mt), GET_ADDR(lamport.pre_images, msgNumber, LByte), aux, LBit, NBit, mt->num_of_leaf_nodes, msgNumber);

    if (isVerified)
        printf("OTP verified\n");
    else
        printf("OTP not verified\n");

    */


    int time_slot;

    time_t initial_time = time(NULL);

    getNumFromUser("Get time slot: ", &time_slot);

    lamport.ip_values.increment_value = time_slot;

    printf("%lld\n\r", initial_time);

    generate_keys_with_ip(LBit, NBit, lamport.numberOfMsg, lamport.ip_values, 1, &lamport.pre_images, &lamport.hash_images);

    mt = init_mt(lamport.hash_images, lamport.numberOfMsg, NByte, __otp_fill_mt_leaf_nodes);

    // Generate root hash, public key
    build_mt(mt, NByte);

    aux = malloc(mt->height * NByte * sizeof(char));

    //change_bit_service(aux, mt->height * NByte, "aux");
    unsigned char *out = malloc(LByte * sizeof(char));
    int day;

    getNumFromUser("Get day to login: ", &day);

    generate_totp(lamport.ip_values.IP, lamport.ip_values.increment_value, lamport.aes_key, LByte, day, out);

    msgNumber = calculate_index(initial_time, initial_time + day * 24 * 60 *60 , time_slot);

    printf("index in merkle tree leaves %d\n", msgNumber);

    mt_generate_aux(mt, msgNumber, NByte, aux);

    //change_bit_service(aux, mt->height * NByte, "aux");

    isVerified = verify_otp(GET_ROOT_HASH(mt), out, aux, LBit, NBit, mt->num_of_leaf_nodes, msgNumber);

    if (isVerified)
        printf("TOTP verified\n");
    else
        printf("TOTP not verified\n");


    return 0;
}

