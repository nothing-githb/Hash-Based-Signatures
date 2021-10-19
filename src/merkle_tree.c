//
// Created by Halis Şahin on 19.09.2021.
//
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <math.h>
#include <merkle_tree.h>
#include <lamport.h>
#include <helper.h>

static inline unsigned int nextPowerOf2(unsigned int n)
{
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n++;
    return n;
}

void get_aux_list(int index, int *array, int num_of_leaf_nodes)
{
    int i = 0, height, next_power_of_two, num_of_nodes;
    mt_t *mt = malloc(sizeof(mt_t));

    next_power_of_two = nextPowerOf2(num_of_leaf_nodes);
    height = log2(next_power_of_two);
    num_of_nodes = (next_power_of_two * 2 - 1) - (next_power_of_two - num_of_leaf_nodes);

    num_of_nodes -= 1;
    index = (1 << height) - 1 + index;
    while(0 < index)
    {
        if (1 == (index & 1)) // index is odd
        {
            if (index < num_of_nodes)
                array[i++] = index + 1;
            else
                array[i++] = -1;

            index = (index - 1) / 2;
        }
        else    // index is even
        {
            array[i++] = index - 1;
            index = (index - 2) / 2;
        }
        if (1 == (num_of_nodes & 1))
            num_of_nodes = (num_of_nodes - 1) / 2;
        else
            num_of_nodes = (num_of_nodes - 2) / 2;
    }
}

mt_node_t *init_mt(ADDR public_keys, const UINT4 number_of_msg, const UINT4 NByte, void (*fill_leaf_nodes)(mt_t* mt, ADDR data, __maybe_unused const UINT4 arg1))
{
    int next_power_of_two;
    mt_t *mt = malloc(sizeof(mt_t));

    next_power_of_two = nextPowerOf2(number_of_msg);
    mt->height = log2(next_power_of_two);
    mt->num_of_leaf_nodes = number_of_msg;
    mt->num_of_nodes = (next_power_of_two * 2 - 1) - (next_power_of_two - number_of_msg);

    // TODO revise with calloc
    mt->nodes = malloc(mt->num_of_nodes * sizeof(mt_node_t)); // Allocate memory for merkle tree nodes
    memset(mt->nodes, 0, mt->num_of_nodes * sizeof(mt_node_t));   // Fill memory with zeros

    (*fill_leaf_nodes)(mt, public_keys, NByte); // Fill leaf nodes

    return mt;
}

void build_mt(mt_t *mt, const UINT4 NByte)
{
    int i, offset, left_index, right_index;
    int public_key_size = lamport.combValues.n * NByte;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;

    offset = mt->num_of_nodes - mt->num_of_leaf_nodes;

    // Fill the internal nodes
    for (i = offset - 1; i >= 0; i--)
    {
        left_index = GET_LEFT_INDEX(i);
        if (left_index <= (mt->num_of_nodes - 1))
        {
            if (NULL != mt->nodes[left_index].hash)
            {
                crypto_hash_sha512_init(&state);
                crypto_hash_sha512_update(&state, mt->nodes[left_index].hash, NByte);

                right_index = GET_RIGHT_INDEX(i);

                if (right_index <= (mt->num_of_nodes - 1))
                    if (NULL != mt->nodes[right_index].hash)
                        crypto_hash_sha512_update(&state, mt->nodes[right_index].hash, NByte);

                crypto_hash_sha512_final(&state, msgHash512);

                mt->nodes[i].hash = malloc(NByte * sizeof(char));
                memcpy(mt->nodes[i].hash, msgHash512, NByte);

                if (PRINT)
                {
                    printf("%d\n", i);
                    printBytes("internal", mt->nodes[i].hash, NByte);
                }
            }
            else
            {
                mt->nodes[i].hash = NULL;
            }
        }
        else
        {
            mt->nodes[i].hash = NULL;
        }
    }
}

void mt_generate_aux(mt_t *mt, const UINT4 index_of_msg, const UINT4 NByte, ADDR aux)
{
    int i, aux_list[mt->height];
    ADDR addr = aux;

    get_aux_list(index_of_msg, aux_list, mt->num_of_leaf_nodes);

    for (i = 0; i < mt->height; i++)
    {
        if (-1 == aux_list[i])
            continue;
        memcpy(addr, mt->nodes[aux_list[i]].hash, NByte);
        addr += NByte;
        if (DEBUG)
        {
            printf("%d\n", aux_list[i]);
            printBytes("node hash", mt->nodes[aux_list[i]].hash, NByte);
        }
    }
}

BOOL mt_verify_public_with_aux(ADDR public_key, ADDR sent_hash, ADDR aux, UINT4 index_of_msg, UINT4 num_of_leaf_nodes, UINT4 NByte)
{
    unsigned char msg_hash_512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    int i = 0, mt_height, next_power_of_two, num_of_nodes;
    ADDR addr = aux;

    next_power_of_two = nextPowerOf2(num_of_leaf_nodes);
    mt_height = log2(next_power_of_two);
    int aux_list[mt_height];

    get_aux_list(index_of_msg, aux_list, num_of_leaf_nodes);

    memcpy(msg_hash_512, sent_hash, NByte);

    for (i = 0;i < mt_height; i++)
    {
        crypto_hash_sha512_init(&state);

        if (aux_list[i] > 0 && 0 == (aux_list[i] % 2))
        {
            crypto_hash_sha512_update(&state, msg_hash_512, NByte);
            crypto_hash_sha512_update(&state, addr, NByte);
            addr += NByte;
        }
        else if(aux_list[i] > 0 && 1 == (aux_list[i] % 2))
        {
            crypto_hash_sha512_update(&state, addr, NByte);
            crypto_hash_sha512_update(&state, msg_hash_512, NByte);
            addr += NByte;
        }
        else // -1 == aux_list[i]
        {
            crypto_hash_sha512_update(&state, msg_hash_512, NByte);
        }
        crypto_hash_sha512_final(&state, msg_hash_512);
    }

    return (0 == memcmp(msg_hash_512, public_key, NByte));

}



