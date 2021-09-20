//
// Created by Halis Şahin on 19.09.2021.
//
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include <merkle_tree.h>

mt_node_t *mt = NULL;
unsigned int height;
unsigned int numOfNodes;
unsigned int nextPowerOfTwo;
unsigned int numOfMsg;

unsigned int nextPowerOf2(unsigned int n)
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

mt_node_t* build_mt(msg_node *messages, int numberOfMsg, int NByte)
{
    unsigned char msgHash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha256_state state;
    mt_node_t *nodes = NULL;
    mt_node_t *tmp_node;
    int i, offset, left_index, right_index;
    nextPowerOfTwo = nextPowerOf2(numberOfMsg);
    numOfMsg = numberOfMsg;
    numOfNodes = (nextPowerOfTwo * 2 - 1) - (nextPowerOfTwo - numOfMsg);

    nodes = calloc(1, numOfNodes * sizeof(mt_node_t));

    offset = numOfNodes - numOfMsg;

    for (i = 0; i < numOfMsg; i++)
    {
        tmp_node = &nodes[offset];
        crypto_hash_sha512(msgHash512, messages[i].msg, NByte);
        tmp_node->hash = malloc(NByte * sizeof(char));
        memcpy(tmp_node->hash, msgHash512, NByte);
    }

    for (i = offset - 1; i >= 0; i--)
    {
        left_index = GET_LEFT_INDEX(i);
        if (left_index >= (numOfNodes - 1))
        {
            if (NULL != GET_NODE(nodes, left_index)->hash)
            {
                crypto_hash_sha256_init(&state);

                tmp_node = GET_NODE(nodes, left_index);
                crypto_hash_sha256_update(&state, tmp_node->hash, NByte);

                right_index = GET_RIGHT_INDEX(i);
                if (right_index >= (numOfNodes - 1))
                {
                    if (NULL != GET_NODE(nodes, right_index)->hash)
                    {
                        tmp_node = GET_NODE(nodes, right_index);
                        crypto_hash_sha256_update(&state, tmp_node->hash, NByte);
                    }
                }

                crypto_hash_sha256_final(&state, msgHash512);

                tmp_node->hash = malloc(NByte * sizeof(char));
                memcpy(tmp_node->hash, msgHash512, NByte);
            }
            else
            {
                GET_NODE(nodes, i)->hash = NULL;
            }
        }
        else
        {
            GET_NODE(nodes, i)->hash = NULL;
        }
    }

    return nodes;
}
