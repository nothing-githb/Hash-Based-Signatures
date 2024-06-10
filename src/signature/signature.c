//
// Created by Halis Şahin on 19.02.2022.
//

#include <time.h>
#include <sodium.h>
#include <string.h>

#include <signature.h>
#include <spn/spn8.h>
#include <spn/spn16.h>
#include <spn/spn24.h>
#include <spn/spn32.h>

#include "../lamport/Lamport.h"
#include "../merkle_tree/Merkle_tree.h"
#include "../mapping/Mapping.h"
#include "../Config.h"
#include "../Helper.h"

// Get n and p values from mapping array.
#define N               (combination_mapping[NByte - 1][0])
#define P               (combination_mapping[NByte - 1][1])

/**************************  CLIENT SIDE PARAMETERS  **************************/

static uint8_t ip[LByte];          /* (randomly generated and stored) initial plaintext for WBT-EK */
static mt_t *mt = NULL;                             /* merkle tree */
static uint32_t client_state;                       /* client side state */
static uint8_t* hash_images;

/**************************  SERVER SIDE PARAMETERS  **************************/

static uint8_t root_hash[NByte];                    /* root hash */
static uint32_t server_state;                       /* server side state */

/**************************  CLIENT SIDE FUNCTIONS   **************************/

static void __lamport_fill_mt_leaf_nodes(void* merkle_t, uint8_t* data)
{
    int i, offset;
    int public_key_size = N * NByte;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    uint8_t* addr = data;
    mt_t* merkle_tree = (mt_t *) merkle_t;

    offset = merkle_tree->num_of_nodes - merkle_tree->num_of_leaf_nodes;

    // Fill leaf nodes
    for (i = 0; i < merkle_tree->num_of_leaf_nodes; i++)
    {
        crypto_hash_sha512(msgHash512, addr, public_key_size);  // Calculate hash of public key(hash-images)
        merkle_tree->nodes[offset+i].hash = malloc(NByte * sizeof(char));    // Allocate memory for hash
        memcpy(merkle_tree->nodes[offset+i].hash, msgHash512, NByte);    // Copy calculated hash into the node's hash memory
        addr += public_key_size;
        if (PRINT)
        {
            printf("%d\n", offset+i);
            printBytes("leafs", merkle_tree->nodes[offset+i].hash, NByte);
        }
    }
}

uint8_t* init_signature()
{
    tIP_values ip_values;
    /* root hash */
    uint8_t* public_values = malloc(NByte);

    if (NULL == public_values)
    {
        // TODO error action, no memory
        return NULL;
    }

    /* hash-images */
    hash_images = malloc((NUM_OF_MESSAGES * N * NByte));

    if (NULL == hash_images)
    {
        // TODO error action, no memory
        printf("Hata\n");
        return NULL;
    }

    /* randomly generated and stored initial_plaintext */
    randombytes_buf(ip, LByte);

    client_state = 0;       /* initialize client state */

    ip_values.increment_value = 1;
    ip_values.IP = (void *) ip;

    generate_keys_with_ip(N, &ip_values, NUM_OF_MESSAGES, hash_images);

    /* Fill leaf nodes */
    mt = init_mt(hash_images, NUM_OF_MESSAGES, __lamport_fill_mt_leaf_nodes);

    build_mt(mt);               /* build merkle tree */

    /* public key = root hash */
    memcpy(public_values, GET_ROOT_HASH(mt), NByte);

    // free(public_values);

    return public_values;
}

uint8_t* sign_msg(uint8_t* msg)
{
    int i, j, a[P];
    uint8_t* addr;
    uint8_t* hash_addr;
    uint8_t local_ip[LByte];
    uint8_t local_ip_2[LByte];
    uint8_t msg_hash_512[crypto_hash_sha512_BYTES];
    uint8_t* signature;
    mpz_t msgHashValue;

    signature = malloc( (P * LByte)    +    /* pre-images in signature */
                        ((N - P) * NByte)   +    /* hash images except singature's pre-images */
                        ( mt->height * NByte )); /* aux hash values */

    if (NULL == signature)
    {
        // TODO error action, no memory
        return NULL;
    }

    memcpy(local_ip, ip, LByte);    /* ip to local_ip */
    memcpy(local_ip_2, ip, LByte);    /* ip to local_ip */

    int msg_len = LByte; // TODO change
    crypto_hash_sha512(msg_hash_512, msg, msg_len);       /* Calc hash of msg */

    mpz_init(msgHashValue);                /* Init integer message hash value */

    /* Calculate integer message hash value */
    mpz_import(msgHashValue, 1, 1, NByte, 0, 0, msg_hash_512);

    /* Get mapping of msgHashValue (N / P) */
    get_mapping_from_message(msgHashValue, N, P, a);

    mpz_clear(msgHashValue);

    addr = signature;

    /* Get address of hash images at the client state */
    hash_addr = GET_ADDR(hash_images, client_state, N * NByte);

    increment_bytes(local_ip_2, LByte, client_state * N);
    increment_bytes(local_ip, LByte, client_state * N);

    for(i = 0, j = 0; i < N; i++)
    {
        if (i >= (a[P-1]-1) || i != (a[j] - 1))
        {
            memcpy(addr, GET_ADDR(hash_addr, i, NByte), NByte);
            addr += NByte;
        }
        else
        {
            /* generate time-based OTP */
#if N_IN == 8
            encrypt_wb_8((uint8_t*) &local_ip);
#elif N_IN == 16
            encrypt_wb_16((uint16_t*) &local_ip);
#elif N_IN == 24
            encrypt_wb_24((uint8_t*) &local_ip);
#elif N_IN == 32
        encrypt_wb_32((uint32_t*) &local_ip);
#endif
            memcpy(addr, local_ip, LByte);
            addr += LByte;
            j++;
        }
        increment_bytes(local_ip_2, LByte, 1);
        memcpy(local_ip, local_ip_2, LByte);
    }

    /* hash values up to the root node wrt client_state */
    mt_generate_aux(mt, client_state, addr);

    client_state++;                        /* increment the server side state */

    // free(signature);

    return signature;
}

/**************************  SERVER SIDE FUNCTIONS   **************************/

/**
 * These parameters must be known by the server:
 * NUM_OF_MESSAGE, NBit, LBit, N, P (combination values)
 */

void server_init_signature(uint8_t * public_values)
{
    /** public key = ROOT hash **/
    memcpy(root_hash, public_values, NByte);
    server_state = 0;                         /* initialize server side state */
}

int verify_msg(uint8_t* msg, uint8_t* signature)
{
    unsigned char msg_hash_512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    int i, j, a[P];
    int isVerified = 0;
    mpz_t msgHashValue;
    uint8_t* addr;

    int msg_len = LByte; // TODO change
    crypto_hash_sha512(msg_hash_512, msg, msg_len);       /* Calc hash of msg */

    /* Calculate message hash value */
    mpz_init(msgHashValue);

    mpz_import(msgHashValue, 1, 1, NByte, 0, 0, msg_hash_512);

    get_mapping_from_message(msgHashValue, N, P, a);

    mpz_clear(msgHashValue);

    addr = signature;

    crypto_hash_sha512_init(&state);

    for (i = 0, j = 0; i < N; i++)
    {
        if (i >= (a[P-1]-1) || i != (a[j] - 1))
        {
            crypto_hash_sha512_update(&state, addr, NByte);
            addr += NByte;
        }
        else
        {
            crypto_hash_sha512(msg_hash_512, addr, LByte);
            crypto_hash_sha512_update(&state, msg_hash_512, NByte);
            addr += LByte;
            j++;
        }
    }
    crypto_hash_sha512_final(&state, msg_hash_512);

    /* hash values up to the root node wrt server_state */
    isVerified = mt_verify_public_with_aux(root_hash,
                                           msg_hash_512,
                                           addr,
                                           server_state,
                                           NUM_OF_MESSAGES);

    if (1 == isVerified) server_state++;   /* increment the server side state */

    return isVerified;
}
