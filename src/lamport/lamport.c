//
// Created by Halis Şahin on 19.08.2021.
//

#include <sodium.h>
#include <signature.h>
#include <string.h>
#include "../Types.h"
#include "../merkle_tree/Merkle_tree.h"
#include "../mapping/Mapping.h"
#include "../Helper.h"
#include "../Config.h"
#if N_IN == 8
#include <spn/spn8.h>
#elif N_IN == 16
#include <spn/spn16.h>
#elif N_IN == 24
#include <spn/spn24.h>
#elif N_IN == 32
#include <spn/spn32.h>
#endif
#include "Lamport.h"

void generate_keys_with_ip(int total_number, tIP_values* ip_values, int num_of_msg, uint8_t* hash_images)
{
    uint8_t msg_hash_512[crypto_hash_sha512_BYTES];
    uint8_t ip[LByte], op[LByte];
    uint8_t* hash_addr;
    int i = 0;
    int j = 0;

    memcpy(ip, ip_values->IP, LByte);  // Copy IP to local ip
    memcpy(op, ip_values->IP, LByte);  // Copy IP to local ip

    hash_addr = hash_images;

    for (j = 0; j < num_of_msg; j++)
    {
        for (i = 0; i < total_number; i++)
        {
#if N_IN == 8
            encrypt_wb_8(&ip);
#elif N_IN == 16
            encrypt_wb_16(&ip);
#elif N_IN == 24
            encrypt_wb_24(&ip);
#elif N_IN == 32
            encrypt_wb_32(&ip);
#endif
            /* Calc hash-image */
            crypto_hash_sha512(msg_hash_512, ip, LByte);

            /* IP + k/t */
            increment_bytes(op, LByte, ip_values->increment_value);

#if NByte == 16 && LByte == 16
            *((uint64_t*)hash_addr) = *(((uint64_t*)msg_hash_512));
            *(((uint64_t*)hash_addr)+1) = *(((uint64_t*)msg_hash_512)+1);
            *((uint64_t*)ip) = *(((uint64_t*)op));
            *(((uint64_t*)ip)+1) = *(((uint64_t*)op)+1);
#else
            memcpy(hash_addr, msg_hash_512, NByte);
            memcpy(&ip, &op, LByte);
#endif
            hash_addr += NByte;
        }
    }
}

