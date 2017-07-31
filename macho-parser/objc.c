#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include "parser.h"
#include "mach-o.h"
#include "objc.h"



size_t macho_string_size(uint64_t offset){
    char *buffer = (char*)((uint64_t)gmacho_file->buffer + offset);
    
    size_t size = 0;
    
    for(char *s = buffer; *s; s++) size++;
    
    return size;
}

                           
void macho_parse_objc_64(mach_vm_address_t addr, uint64_t offset, uint64_t size){
    uint64_t *buffer = (uint64_t*)gmacho_file->buffer;
    uint64_t diff = addr - offset;
    uint64_t sect_start = offset;
    uint64_t sect_end = offset + size;
    printf("\tProcessing Objective C Segment at offset 0x%llx\n",offset);
    
    while(offset < sect_end){
        
        uint64_t classptr = *(buffer + offset/sizeof(uint64_t));
        uint64_t classoff = classptr - diff;
        printf("\t\tClass stored at offset 0x%llx\n",classoff);
        
        struct dyld_objc_2_class *class = (struct dyld_objc_2_class*)macho_load_bytes((uint32_t)classoff,sizeof(struct dyld_objc_2_class));
        
        uint64_t dataptr = (uint64_t)class->data;
        uint64_t dataoff = dataptr - diff;
        
        struct dyld_objc_2_class_data *data = (struct dyld_objc_2_class_data*)macho_load_bytes((uint32_t)dataoff,sizeof(struct dyld_objc_2_class_data));
        
        size_t size = macho_string_size(data->name - diff);
        
        char *name = macho_load_bytes((uint32_t)data->name - (uint32_t)diff,sizeof(char) * (uint32_t)size);
        printf("\t\t$OBJC_CLASS_%s\n",name);
        
        free(class);
        free(data);
        free(name);
        offset += sizeof(uint64_t);
    }
    
}
