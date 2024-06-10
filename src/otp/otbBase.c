//
// Created by Halis Şahin on 19.02.2022.
//
#include <string.h>         /* memcpy */
#include <stdlib.h>

#include "../merkle_tree/Merkle_tree.h"    /* merkle tree */
#include "../Config.h"

void __otp_fill_mt_leaf_nodes(void* mt, uint8_t* data)
{
    mt_t* merkle_tree = (mt_t *) mt;
    uint8_t* addr = data;
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



