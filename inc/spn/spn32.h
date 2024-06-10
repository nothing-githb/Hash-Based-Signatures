//
// Created by Halis Şahin on 13.02.2022.
//

#ifndef SPNBOX_SPN32_H
#define SPNBOX_SPN32_H

#include <stdint.h>

void encrypt_wb_32(uint32_t* plain_text);

void encrypt_bb_32(uint32_t* plain_text, uint8_t* extended_key);

#endif //SPNBOX_SPN32_H
