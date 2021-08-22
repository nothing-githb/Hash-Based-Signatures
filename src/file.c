#include <stdio.h>      // FILE, puts, fwrite
#include <stdlib.h>     // exit
#include <fcntl.h>      // O_RDONLY
#include <sys/stat.h>   // fstat
#include <sys/types.h>  // mmap
#include <sys/mman.h>   // PROT_READ, MAP_SHARED, mmap
#include <string.h>     // memcpy

#include <file.h>

static inline unsigned long get_size_by_fd(int fd) 
{
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

void readFile(const char *fileName, char *fileBuffer, unsigned long *fileSize)
{
    int fd;

    fd = open(fileName, O_RDONLY);

    if(fd < 0) 
    {
        puts("Message unreadable");
        exit(-1);
    }
    *fileSize = get_size_by_fd(fd);
    fileBuffer = (char *) mmap(0, *fileSize, PROT_READ, MAP_SHARED, fd, 0);
}

// void writeToFile(const char *fileName, void *ptr1, size_t size1, int nitem1, 
//     void *ptr2, size_t size2, int nitem2)
// {
//     FILE *file;
//     file = fopen(fileName, "r");
//     if (NULL != file)
//     {
//         fwrite(ptr1, size1, nitem1, file);
//         fwrite(ptr2, size2, nitem2, file);
//         fclose (file);
//     } 
//     else 
//     { 
//         printf("Cannot write file: %s\n", fileName); 
//         exit(-1); 
//     }
// }
