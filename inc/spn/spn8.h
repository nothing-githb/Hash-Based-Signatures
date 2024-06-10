//
// Created by Halis Şahin on 7.02.2022.
//

#ifndef SPNBOX_SPN8_H
#define SPNBOX_SPN8_H

#include <stdint.h>

void encrypt_wb_8(uint8_t* plain_text);

void encrypt_bb_8(uint8_t* plain_text, uint8_t* extended_key);

#endif //SPNBOX_SPN8_H
