//
// Created by Halis Şahin on 19.09.2021.
//

#ifndef MCS_MERKLE_TREE_H
#define MCS_MERKLE_TREE_H

#include <types.h>


#define GET_LEFT_INDEX(i)           ( ( (i) * 2 ) + 1)
#define GET_RIGHT_INDEX(i)          ( ( (i) * 2 ) + 2)

#define GET_ROOT_HASH(mt)           ( mt->nodes[0].hash )


typedef struct mt_node {
    ADDR hash;
}mt_node_t;

typedef struct merkle_tree{
    mt_node_t *nodes;
    int height;
    int num_of_nodes;
    int num_of_leaf_nodes;
    void (*fill_leaf_nodes)(ADDR mt, ADDR data, __maybe_unused const UINT4 arg1);
}mt_t;

mt_node_t *init_mt(ADDR public_keys, const UINT4 number_of_msg, const UINT4 NByte, void (*fill_leaf_nodes)());

void build_mt(mt_t *mt, const UINT4 NByte);

mt_node_t *build_mt_otp(ADDR public_keys, int number_of_msg, int NByte);

void get_aux_list(int index, int *array, int mt_height);

void mt_generate_aux(mt_t *mt, const UINT4 index_of_msg, const UINT4 NByte, ADDR aux);

BOOL mt_verify_public_with_aux(ADDR public_key, ADDR sent_hash, ADDR aux, UINT4 index_of_msg, UINT4 num_of_leaf_nodes, UINT4 NByte);

#endif //MCS_MERKLE_TREE_H
