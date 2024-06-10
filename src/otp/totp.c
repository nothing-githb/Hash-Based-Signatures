//
// Created by Halis Şahin on 19.02.2022.
//

#include <time.h>
#include <sodium.h>
#include <string.h>

#include <totp.h>
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
extern void __otp_fill_mt_leaf_nodes(void* mt, uint8_t* data);

/**************************  CLIENT SIDE PARAMETERS  **************************/

static uint8_t ip[LByte];      /* (randomly generated and stored) initial plaintext for WBT-EK */
static time_t initial_time;                         /* initial time */
static mt_t *mt = NULL;                             /* merkle tree */

/**************************  SERVER SIDE PARAMETERS  **************************/

static time_t server_initial_time;                   /* mt init time */
static uint8_t root_hash[NByte];                     /* root hash */

/**************************  CLIENT SIDE FUNCTIONS   **************************/

uint8_t* init_totp()
{
    /* root hash + initial time */
    uint8_t* public_values = malloc(NByte + sizeof(time_t));
    /* hash-images */
    uint8_t* hash_images = malloc(TOTP_LEAF_NODE * NByte);

    tIP_values ip_values;

    initial_time = time(NULL);

    /* randomly generated and stored initial_plaintext*/
    randombytes_buf(ip, LByte);

    ip_values.increment_value = TIME_SLOT;
    ip_values.IP = (void *) ip;

    generate_keys_with_ip(TOTP_LEAF_NODE, &ip_values, 1, hash_images);

    mt = init_mt(hash_images, TOTP_LEAF_NODE, __otp_fill_mt_leaf_nodes);

    build_mt(mt);               /* build merkle tree */

    /* public key = root + initial time */
    memcpy(public_values, GET_ROOT_HASH(mt), NByte);
    memcpy(public_values+NByte, &initial_time, sizeof(time_t));

    // free(public_values);
    free(hash_images);

    return public_values;
}

uint8_t* generate_totp()
{
    uint8_t* aux = (uint8_t*) malloc(LByte + mt->height * NByte);
    time_t   time_slot = 0;
    uint64_t index = 0;
    uint8_t  local_ip[LByte];
    time_t   current_time = time(NULL);

    memcpy(local_ip, ip, LByte);                         /* Get IP to local_ip */

    time_slot = (current_time - initial_time) - ((current_time - initial_time) % TIME_SLOT);

    increment_bytes(local_ip, LByte, time_slot);    /* IP + T − T_init */

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

    memcpy(aux, local_ip, LByte);

    index = time_slot / TIME_SLOT;

    mt_generate_aux(mt, index, aux + LByte);   /* hash values up to the root node */

    //free(aux);

    return aux;
}

/************************** SERVER SIDE PARAMETERS **************************/

/**
 * These parameters must be known by the server:
 * TOTP_LEAF_NODE, TIME_SLOT, NBit, LBit
 */

/** public key = ROOT hash + merkle tree initial_time **/
void server_init_totp(uint8_t * public_values)
{
    memcpy(root_hash, public_values, NByte);
    memcpy(&server_initial_time, public_values+NByte, sizeof(time_t));
}

int verify_totp(uint8_t* otp_with_aux)
{
    int index;
    time_t time_slot;
    time_t current_time;
    uint8_t msg_hash_512[crypto_hash_sha512_BYTES];

    current_time = time(NULL);

    time_slot = (current_time - initial_time) - ((current_time - initial_time) % TIME_SLOT);

    index = time_slot / TIME_SLOT;

    crypto_hash_sha512(msg_hash_512, otp_with_aux, LByte);

    int isVerified = mt_verify_public_with_aux(root_hash, msg_hash_512, otp_with_aux+LByte, index, TOTP_LEAF_NODE);

    return isVerified;
}

