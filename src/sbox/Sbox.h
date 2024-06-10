//
// Created by Halis Şahin on 8.01.2022.
//

#ifndef SPNBOX_SBOX_H
#define SPNBOX_SBOX_H

#include <stdlib.h>
#include <stdint.h>

#define SB(p)           (SBOX[(p)])

extern const uint8_t SBOX[256];

#endif //SPNBOX_SBOX_H
