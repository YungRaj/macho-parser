#include <stdio.h>
#include "parser.h"

/*
 * macho_load_bytes is a dummy function that loads temporary data from the file onto the heap
 * a better way to do this is use a universal buffer that gets operated on instead and do pointer arithmetic
 * (we learn from our mistakes)
 */

void* macho_load_bytes(uint32_t offset, uint32_t size){
    FILE *mach = gmacho_file->file;
    void *buf = calloc(1,size);
    fseek(mach, offset, SEEK_SET);
    fread(buf, size, 1, mach);
    return buf;
}

size_t macho_string_size(uint64_t offset){
    char *buffer = (char*)((uint64_t)gmacho_file->buffer + offset);
    
    size_t size = 0;
    
    for(char *s = buffer; *s; s++) size++;
    
    return size;
}

char* macho_read_string(uint64_t offset){
    size_t size = macho_string_size(offset);
    return macho_load_bytes((uint32_t)offset,sizeof(char) * (uint32_t)size);
}

