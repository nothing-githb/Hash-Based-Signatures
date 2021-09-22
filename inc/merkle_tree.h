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
}mt_t;

mt_node_t *build_mt(ADDR public_keys, int number_of_msg, int NByte);

void getAuxList(int index, int *array, int mt_height);


#endif //MCS_MERKLE_TREE_H
