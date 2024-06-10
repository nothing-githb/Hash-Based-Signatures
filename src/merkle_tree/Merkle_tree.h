//
// Created by Halis Şahin on 19.09.2021.
//

#ifndef MCS_MERKLE_TREE_H
#define MCS_MERKLE_TREE_H

#include "../Types.h"
#include <stdint.h>

#define GET_LEFT_INDEX(i)           ( ( (i) * 2 ) + 1)
#define GET_RIGHT_INDEX(i)          ( ( (i) * 2 ) + 2)

#define GET_ROOT_HASH(mt)           ( mt->nodes[0].hash )


typedef struct mt_node {
    void* hash;
}mt_node_t;

typedef struct Merkle_tree{
    mt_node_t *nodes;
    int height;
    int num_of_nodes;
    int num_of_leaf_nodes;
}mt_t;

mt_t *init_mt(void* public_keys,
              const unsigned int number_of_msg,
              void (*fill_leaf_nodes)());

void build_mt(mt_t *mt);

void get_aux_list(int index, int *array, int mt_height);

void mt_generate_aux(mt_t *mt, const unsigned int index_of_msg, uint8_t* aux);

int mt_verify_public_with_aux(uint8_t* public_key,
                              uint8_t* sent_hash,
                              uint8_t* aux,
                              unsigned int index_of_msg,
                              unsigned int num_of_leaf_nodes);

#endif //MCS_MERKLE_TREE_H
