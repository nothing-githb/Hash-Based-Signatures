//
// Created by Halis Şahin on 13.02.2022.
//

#ifndef SPNBOX_SPN24_H
#define SPNBOX_SPN24_H

#include <stdint.h>

void encrypt_wb_24(uint8_t* plain_text);

void encrypt_bb_24(uint8_t* plain_text, uint8_t* extended_key);

#endif //SPNBOX_SPN24_H
