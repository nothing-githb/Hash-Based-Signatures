#ifndef FILE_H
#define FILE_H

#include <stddef.h>

void readFile(const char *fileName, char *fileBuffer, unsigned long *fileSize);

void writeToFile(const char *fileName, void *ptr1, size_t size1, int nitem1,
        void *ptr2, size_t size2, int nitem2);

#endif //FILE_H