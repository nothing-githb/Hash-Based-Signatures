//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <lamport.h>
#include <string.h>
#include <types.h>
#include <merkle_tree.h>
#include <mapping.h>
#include <helper.h>
#include <openssl/aes.h>
#include <crypto.h>

tLamport lamport = {
        .combValues.p = 0,
        .combValues.n = 0,
        .signature = NULL,
        .pre_images = NULL,
        .hash_images = NULL,
        .msgHash = NULL,
        .messages = NULL,
        .numberOfMsg = 0,
        .ip_values = {0},
        .aes_key = {0}
};

void __lamport_fill_mt_leaf_nodes(ADDR mt, ADDR data, const UINT4 NByte)
{
    int i, offset;
    int public_key_size = lamport.combValues.n * NByte;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    ADDR addr = data;
    mt_t* merkle_tree = (mt_t *) mt;

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

void generate_keys_with_ip(int len, int hash_len, int total_number, tIP_values ip_values, int num_of_msg, ADDR* pre_images, ADDR* hash_images)
{
    unsigned char msg_hash_512[crypto_hash_sha512_BYTES];
    int LByte = len / 8, NByte = hash_len / 8;
    unsigned char ip[LByte], out[LByte], key[16];
    AES_KEY AESKey; // FIXME must be removed
    int i, j;

    // FIXME there is no need the key in new WBT-Ek
    randombytes_buf(key, 16);   // Generate random key
    AES_set_encrypt_key(&key, 128, &AESKey);    // Set AES encryption key

    memcpy(ip, ip_values.IP, LByte);  // Copy IP to local ip
    memcpy(&lamport.aes_key, &AESKey, sizeof(AES_KEY));

    *pre_images = malloc(num_of_msg * total_number * LByte * sizeof(char));    // Allocate memory for pre-images
    *hash_images = malloc(num_of_msg * total_number * NByte * sizeof(char));    // Allocate memory for hash-images

    printf("%d pre-image and hash-images created\n", num_of_msg * total_number);

    for (j = 0; j < num_of_msg; j++)
    {
        for (i = 0; i < total_number; i++)
        {
            encryptWithGivenSize(ip, out, &AESKey, LByte);
            increment_bytes(ip, LByte,ip_values.increment_value);
            memcpy(GET_ADDR((*pre_images), j * total_number + i, LByte), out, LByte);      // TODO optimize addr calc
            crypto_hash_sha512(msg_hash_512, out, LByte);
            memcpy(GET_ADDR((*hash_images), j * total_number + i, NByte), msg_hash_512, NByte);    // TODO optimize addr calc
            if (DEBUG)
            {
                printf("%d ", i);
                printBytes("pre-image", GET_ADDR((*pre_images), i, LByte), LByte);
                printBytes("hash-image", GET_ADDR((*hash_images), i, NByte), NByte);
            }
        }
    }
}

/**
 * TODO change with white-box
 * for 1≤s≤N
 *  if h′ = 0
 *      computers,1,t = WBT-EK(IP+t∗2N+2s−1)
 *      reveal rs,1,t and f(rs,2,t)
 *  else
 *      computers,2,t = WBT-EK(IP+t∗2N+2s)
 *      reveal f(rs,1,t) and rs,2,t
 *
 */
void sign_msg(ADDR msg_hash, ADDR pre_images, ADDR hash_images, int LBit, int NBit, ADDR mt, int index_of_msg)
{
    mt_t *merkle_tree = (mt_t *) mt;
    int i, j, a[lamport.combValues.p];
    ADDR addr;
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;

    // Calculate message hash value
    mpz_init(msgHashValue);
    // mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    mpz_import(msgHashValue, 1, 1, LByte, 0, 0, msg_hash);

    lamport.signature = malloc( (lamport.combValues.p * LByte)          // pre-images in signature
            + ( (lamport.combValues.n - lamport.combValues.p) * NByte )      // hash images except singature's pre-images
            + ( merkle_tree->height * NByte )                                // aux
            );

    if (PRINT) printf("Size of signature : %d bit, %d byte\n", lamport.combValues.p * LBit, lamport.combValues.p * LByte);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    addr = lamport.signature;

    for(i = 0, j = 0; i < lamport.combValues.n; i++)
    {
        if (i >= (a[lamport.combValues.p-1]-1) || i != (a[j] - 1))
        {
            memcpy(addr, GET_ADDR(hash_images, i, NByte), NByte);
            addr += NByte;
        }
        else
        {
            memcpy(addr, GET_ADDR(pre_images, i, LByte), LByte);
            addr += LByte;
            j++;
        }
    }

    mt_generate_aux(merkle_tree, index_of_msg, NByte, addr);

    return;
}

BOOL verify_msg(ADDR public_key, ADDR signature, ADDR msgHash, int LBit, int NBit, int mt_num_of_leaf_nodes, int index_of_msg)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    int i, j, a[lamport.combValues.p];
    int LByte = LBit / 8, NByte = NBit / 8;
    mpz_t msgHashValue;
    ADDR addr;

    // Calculate message hash value
    mpz_init(msgHashValue);

    // mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
    mpz_import(msgHashValue, 1, 1, NByte, 0, 0, msgHash);

    get_mapping_from_message(msgHashValue, lamport.combValues.n, lamport.combValues.p, a);

    mpz_clear(msgHashValue);

    addr = signature;

    crypto_hash_sha512_init(&state);
    for (i = 0, j = 0; i < lamport.combValues.n; i++)
    {
        if (i >= (a[lamport.combValues.p-1]-1) || i != (a[j] - 1))
        {
            crypto_hash_sha512_update(&state, addr, NByte);
            addr += NByte;
        }
        else
        {
            crypto_hash_sha512(msgHash512, addr, LByte);
            crypto_hash_sha512_update(&state, msgHash512, NByte);
            addr += LByte;
            j++;
        }
    }
    crypto_hash_sha512_final(&state, msgHash512);

    return mt_verify_public_with_aux(public_key, msgHash512, addr, index_of_msg, mt_num_of_leaf_nodes, NByte);
}
