
#ifndef __parser_h
#define __parser_h

#define swap(x,y,s) if(s) swap_ ## x(y,NXHostByteOrder())
#define swapn(x,y,n,s) if(s) swap_ ## x(y,n,NXHostByteOrder())

typedef struct{
    FILE *file;
    char *buffer;
    size_t size;
} macho_file;

extern macho_file *gmacho_file;

#endif
