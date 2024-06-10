//
// Created by Halis Şahin on 16.01.2022.
//

#ifndef SPNBOX_TABLES_H
#define SPNBOX_TABLES_H

#define GET_TABLE(matrix, i, j, type)  (type*)((matrix)[i][j])
#define MUL(table, p, type)            ((table)[(type)(p)])

#define _TABLE(bit, hex)            table_##bit##_0x##hex
#define TABLE(bit, hex)             _TABLE(bit, hex)
#define T_16(hex)                   (_TABLE(16, hex))
#define T_8(hex)                   (_TABLE(8, hex))
#define TABLE_ADDR(bit ,hex)        (ADDR)&_TABLE(bit, hex)

#endif //SPNBOX_TABLES_H
