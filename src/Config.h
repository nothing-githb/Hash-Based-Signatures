//
// Created by Halis Şahin on 9.01.2022.
//

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

/* SPNBox-in 8/16/24-(32 not recommended) */
#define N_IN                16
#define NUM_OF_BYTES        (N_IN/8)
#define ENABLE_OPT          1           /* Only 16 bit */

/* LBit : the length of random numbers (as well as block length of Ek) */
#define LBit                128
#define LByte               (LBit / 8)
/* Nbit is hash length */
#define NBit                128
#define NByte               (NBit / 8)

/* Lamport */
#define NUM_OF_MESSAGES      32768

/* TOTP */
#define TIME_SLOT           5
#define TOTP_LEAF_NODE      32768

/* Debug */
#define SBC_DEBUG           0
#define MC_DEBUG            0
#define KC_DEBUG            0
#define OUTER_DEBUG         0
#define LT_DEBUG            0

#endif //SPNBOX_CONFIG_H
