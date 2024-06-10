//
// Created by Halis Şahin on 7.02.2022.
//

#ifndef SPNBOX_SPN16_H
#define SPNBOX_SPN16_H

#include <stdint.h>

void encrypt_wb_16(uint16_t* plain_text);

void encrypt_bb_16(uint16_t* plain_text, uint8_t* extended_key);

#endif //SPNBOX_SPN16_H
