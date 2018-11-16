
#ifndef __parser_h
#define __parser_h

#define swap32(x) OSSwapInt32(x)
#define swap(x,y,s) if(s) swap_ ## x(y,NXHostByteOrder())
#define swapn(x,y,n,s) if(s) swap_ ## x(y,n,NXHostByteOrder())

#include <stdbool.h>

typedef struct{
    uint32_t num_symbols;
    char **symbols;
} symbol_table;

typedef struct{
    bool fat;
    bool is64bit;
    bool arm;
    bool x86;
    char *path;
    FILE *file;
    char *buffer;
    size_t size;
    symbol_table *symboltable;
} macho_file;

extern macho_file *gmacho_file;

void* macho_load_bytes(uint32_t offset, uint32_t size);
size_t macho_string_size(uint64_t offset);
char* macho_read_string(uint64_t offset);


#endif
