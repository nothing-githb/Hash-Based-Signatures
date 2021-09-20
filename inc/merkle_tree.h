//
// Created by Halis Şahin on 19.09.2021.
//

#ifndef MCS_MERKLE_TREE_H
#define MCS_MERKLE_TREE_H

#include <lamport.h>

#define GET_NODE(nodes, i)          ( &nodes[i] )
#define GET_PARENT_INDEX(i)         ( ( (i) - 1) / 2 )
#define GET_SIBLING_INDEX(i)        ( ( ( (i) % 2) == 0) ? ( (i) - 1 ) : ( (i) + 1 ) )
#define GET_LEFT_INDEX(i)           ( ( (i) * 2 ) + 1)
#define GET_RIGHT_INDEX(i)          ( ( (i) * 2 ) + 2)


typedef struct mt_node {
    unsigned char *hash;
}mt_node_t;

extern mt_node_t *mt;

mt_node_t* build_mt(msg_node *messages, int numberOfMsg, int NByte);



#endif //MCS_MERKLE_TREE_H
