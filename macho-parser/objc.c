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

char* macho_read_string(uint64_t offset){
    size_t size = macho_string_size(offset);
    return macho_load_bytes((uint32_t)offset,sizeof(char) * (uint32_t)size);
}

void macho_parse_objc_methods(mach_vm_address_t diff, uint64_t offset, uint64_t n){
    uint64_t off = offset + sizeof(struct _objc_2_class_method_info);
    
   for(int i=0; i<n; i++){
       struct _objc_method *method = macho_load_bytes((uint32_t)off,sizeof(struct _objc_method));
       char *methodname = macho_read_string((uint64_t)method->name - diff);
       printf("\t\t\t0x%08llx: %s\n",method->offset,methodname);
       
       free(method);
       off += sizeof(struct _objc_method);
    }
}

                           
void macho_parse_objc_64(mach_vm_address_t addr, uint64_t offset, uint64_t size){
    uint64_t *buffer = (uint64_t*)gmacho_file->buffer;
    uint64_t diff = addr - offset;
    uint64_t sect_end = offset + size;
    printf("\tProcessing Objective C Segment at offset 0x%llx\n",offset);
    
    while(offset < sect_end){
        
        uint64_t classptr = *(buffer + offset/sizeof(uint64_t));
        uint64_t classoff = classptr - diff;
        
        struct _objc_2_class *class = (struct _objc_2_class*)macho_load_bytes((uint32_t)classoff,sizeof(struct _objc_2_class));
        
        uint64_t dataptr = (uint64_t)class->data;
        uint64_t dataoff = dataptr - diff;
        
        struct _objc_2_class_data *data = (struct _objc_2_class_data*)macho_load_bytes((uint32_t)dataoff,sizeof(struct _objc_2_class_data));
        
        char *name = macho_read_string(data->name - diff);
        printf("\t\t$OBJC_CLASS_%s\n",name);
        
        uint64_t methodinfoptr = data->methods;
        
        if(methodinfoptr){
            uint64_t methodinfooff = methodinfoptr - diff;
            struct _objc_2_class_method_info *method_info = (struct _objc_2_class_method_info*)macho_load_bytes((uint32_t)methodinfooff,sizeof(struct _objc_2_class_method_info));
            
            uint64_t methodcount = method_info->count;
            uint64_t entrysize = method_info->entrySize;
            
            macho_parse_objc_methods(diff,methodinfooff,methodcount);
            free(method_info);
        }
        
        
        free(class);
        free(data);
        free(name);
        offset += sizeof(uint64_t);
    }
    
}
