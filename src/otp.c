//
// Created by Halis Şahin on 10.10.2021.
//

#include <merkle_tree.h>    /* merkle tree */
#include <types.h>          /* ADDR, UINT4 */
#include <sodium.h>
#include <string.h>         /* memcpy */
#include <mapping.h>        /* get_mapping_from_message */
#include <helper.h>
#include <crypto.h>

void __otp_fill_mt_leaf_nodes(ADDR mt, ADDR data, const UINT4 NByte)
{
    mt_t* merkle_tree = (mt_t *) mt;
    ADDR addr = data;
    int i, offset;

    offset = merkle_tree->num_of_nodes - merkle_tree->num_of_leaf_nodes;

    // TODO optimize with single memcpy
    // Fill leaf nodes
    for (i = 0; i < merkle_tree->num_of_leaf_nodes; i++)
    {
        merkle_tree->nodes[offset+i].hash = malloc(NByte * sizeof(char));
        memcpy(merkle_tree->nodes[offset+i].hash, addr, NByte);
        addr += NByte;
    }
}

int calculate_index(time_t initial_time, time_t current_time, int time_slot)
{
    int diff;
    current_time = current_time - (current_time % time_slot);
    initial_time = initial_time - (initial_time % time_slot);
    diff = (current_time - initial_time);
    return ((int) diff) / time_slot;
}

void generate_totp(ADDR IP, int time_slot, AES_KEY aes_key, int LByte, int day, char *out)
{
    unsigned char ip[LByte];
    int current_time;

    memcpy(ip, IP, LByte);

    current_time = (day * 24 * 60 * 60);

    //printf("current time : %lld\n", current_time);

    increment_bytes(ip, LByte, current_time);

    encryptWithGivenSize(ip, out, &aes_key, LByte);

    return;
}

BOOL verify_otp(ADDR public_key, ADDR otp, ADDR aux, int LBit, int NBit, int mt_num_of_leaf_nodes, int index_of_msg)
{
    unsigned char msg_hash_512[crypto_hash_sha512_BYTES];
    int LByte = LBit / 8, NByte = NBit / 8;

    crypto_hash_sha512(msg_hash_512, otp, LByte);

    return mt_verify_public_with_aux(public_key, msg_hash_512, aux, index_of_msg, mt_num_of_leaf_nodes, NByte);
}