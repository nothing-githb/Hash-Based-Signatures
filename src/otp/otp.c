//
// Created by Halis Şahin on 19.02.2022.
//

#include <time.h>
#include <sodium.h>
#include <string.h>

#include <otp.h>
#include <spn/spn8.h>
#include <spn/spn16.h>
#include <spn/spn24.h>
#include <spn/spn32.h>

#include "../lamport/Lamport.h"
#include "../merkle_tree/Merkle_tree.h"
#include "../Config.h"
#include "../Helper.h"

/**
 * Merkle tree filling function for otp.
 * @param mt
 * @param data
 */
extern void __otp_fill_mt_leaf_nodes(uint8_t* mt, uint8_t* data);

/**************************  CLIENT SIDE PARAMETERS  **************************/

static uint8_t ip[LByte];       /* (randomly generated and stored) initial plaintext for WBT-EK */
static mt_t *mt = NULL;                             /* merkle tree */
static uint32_t client_state;                       /* client side state */

/**************************  SERVER SIDE PARAMETERS  **************************/

static uint8_t root_hash[NByte];                    /* root hash */
static uint32_t server_state;                       /* server side state */

/**************************  CLIENT SIDE FUNCTIONS   **************************/

uint8_t* init_otp()
{
    /* root hash + initial time */
    uint8_t* public_values = malloc(NByte);
    /* hash-images */
    uint8_t* hash_images = malloc(TOTP_LEAF_NODE * NByte);

    tIP_values ip_values;

    /* randomly generated and stored initial_plaintext*/
    randombytes_buf(ip, LByte);

    client_state = 0;       /* initialize client state */

    ip_values.increment_value = 1;
    ip_values.IP = (void *) ip;

    generate_keys_with_ip(TOTP_LEAF_NODE, &ip_values, 1, hash_images);

    mt = init_mt(hash_images, TOTP_LEAF_NODE, __otp_fill_mt_leaf_nodes);

    build_mt(mt);               /* build merkle tree */

    /* public key = root + initial time */
    memcpy(public_values, GET_ROOT_HASH(mt), NByte);

    // free(public_values);
    free(hash_images);

    return public_values;
}

uint8_t* generate_otp()
{
    uint8_t* aux = (uint8_t*) malloc(LByte + mt->height * NByte);
    uint8_t  local_ip[LByte];
    memcpy(local_ip, ip, LByte);                        /* Get IP to local_ip */

    increment_bytes(local_ip, LByte, client_state);   /* IP + state */

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

    memcpy(aux, local_ip, LByte);                       /* otp */

    /* hash values up to the root node wrt client_state */
    mt_generate_aux(mt, client_state, aux + LByte);

    client_state++;                        /* increment the server side state */

    //free(aux);

    return aux;
}

/************************** SERVER SIDE PARAMETERS **************************/

/**
 * These parameters must be known by the server:
 * TOTP_LEAF_NODE, NBit, LBit
 */

void server_init_otp(uint8_t * public_values)
{
    /** public key = ROOT hash **/
    memcpy(root_hash, public_values, NByte);
    server_state = 0;                         /* initialize server side state */
}

int verify_otp(uint8_t* otp_with_aux)
{
    int isVerified = 0;
    uint8_t msg_hash_512[crypto_hash_sha512_BYTES];

    crypto_hash_sha512(msg_hash_512, otp_with_aux, LByte);

    /* hash values up to the root node wrt server_state */
    isVerified = mt_verify_public_with_aux(root_hash,
                                               msg_hash_512,
                                               otp_with_aux + LByte,
                                               server_state,
                                               TOTP_LEAF_NODE);

    if (1 == isVerified) server_state++;   /* increment the server side state */

    return isVerified;
}

