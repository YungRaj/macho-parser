
#ifndef __parser_h
#define __parser_h

#define swap32(x) OSSwapInt32(x)
#define swap(x,y,s) if(s) swap_ ## x(y,NXHostByteOrder())
#define swapn(x,y,n,s) if(s) swap_ ## x(y,n,NXHostByteOrder())

typedef struct{
    FILE *file;
    char *buffer;
    size_t size;
} macho_file;

extern macho_file *gmacho_file;

void* macho_load_bytes(uint32_t offset, uint32_t size);
size_t macho_string_size(uint64_t offset);
char* macho_read_string(uint64_t offset);


#endif
