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

static unsigned int nextPowerOf2(unsigned int n)
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

void getAuxList(int index, int *array, int mt_height)
{
    int i = 0;
    index = (1 << mt_height) - 1 + index;
    while(0 < index)
    {
        if (1 == (index & 1)) // index is odd
        {
            array[i++] = index + 1;
            index = (index - 1) / 2;
        }
        else    // index is even
        {
            array[i++] = index - 1;
            index = (index - 2) / 2;
        }
    }
}

mt_node_t *build_mt(ADDR public_keys, int number_of_msg, int NByte)
{
    int i, offset, left_index, right_index, num_of_nodes, next_power_of_two;
    int public_key_size = lamport.combValues.n * NByte;
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    mt_t *mt = malloc(sizeof(mt_t));
    ADDR addr = public_keys;

    next_power_of_two = nextPowerOf2(number_of_msg);
    mt->height = log2(next_power_of_two);
    mt->num_of_leaf_nodes = number_of_msg;
    mt->num_of_nodes = (next_power_of_two * 2 - 1) - (next_power_of_two - number_of_msg);

    mt->nodes = malloc(mt->num_of_nodes * sizeof(mt_node_t)); // Allocate memory for merkle tree
    memset(mt->nodes, 0, mt->num_of_nodes * sizeof(mt_node_t));   // Fill memory with zeros

    offset = mt->num_of_nodes - number_of_msg;

    // Fill leaf nodes
    for (i = 0; i < number_of_msg; i++)
    {
        crypto_hash_sha512(msgHash512, addr, public_key_size);  // Calculate hash of public key(hash-images)
        mt->nodes[offset+i].hash = malloc(NByte * sizeof(char));    // Allocate memory for hash
        memcpy(mt->nodes[offset+i].hash, msgHash512, NByte);    // Copy calculated hash into the node's hash memory
        addr += public_key_size;
        if (PRINT)
        {
            printf("%d\n", offset+i);
            printBytes("leafs", mt->nodes[offset+i].hash, NByte);
        }
    }

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
                mt->nodes[i].hash = NULL;
        }
        else
            mt->nodes[i].hash = NULL;


    }

    return mt;
}
