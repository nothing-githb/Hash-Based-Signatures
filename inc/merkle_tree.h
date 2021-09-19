//
// Created by Halis Şahin on 19.09.2021.
//

#ifndef MCS_MERKLE_TREE_H
#define MCS_MERKLE_TREE_H

typedef struct merkle_tree_node {
    unsigned char *hash;
    struct merkle_tree_node *leftNode;
    struct merkle_tree_node *rightNode;
}mt_node_t;

typedef struct merkle_tree {
    mt_node_t *root;
    unsigned int treeLevels;
    unsigned int hashLength;
}mt_t;






#endif //MCS_MERKLE_TREE_H
