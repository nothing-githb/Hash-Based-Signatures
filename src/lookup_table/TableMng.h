//
// Created by Halis Şahin on 19.02.2022.
//

#ifndef SPNBOX_TABLEMNG_H
#define SPNBOX_TABLEMNG_H

#include "../Config.h"

#define WBT(p)  (lookup_table[*p])

#if 8 == N_IN
extern uint8_t lookup_table[1<<N_IN];
#elif 16 == N_IN
extern uint16_t lookup_table[1<<N_IN];
#elif 24 == N_IN
extern uint32_t lookup_table[1<<N_IN];
#elif 32 == N_IN
extern uint32_t lookup_table[1<<N_IN];
#endif

void get_looktable_fromfile();

#endif //SPNBOX_TABLEMNG_H
