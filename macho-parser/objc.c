#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

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

void macho_parse_objc_methods(mach_vm_address_t diff, uint64_t offset, uint64_t n, bool metaclass){
    uint64_t off = offset + sizeof(struct _objc_2_class_method_info);
    
    printf("\t\t\tMethods\n");
    
    for(int i=0; i<n; i++){
        struct _objc_method *method = macho_load_bytes((uint32_t)off,sizeof(struct _objc_method));
        char *methodname = macho_read_string((uint64_t)method->name - diff);
        
        if(metaclass)
            printf("\t\t\t\t0x%08llx: +%s\n",method->offset,methodname);
        else
            printf("\t\t\t\t0x%08llx: -%s\n",method->offset,methodname);
        
        free(method);
        free(methodname);
        off += sizeof(struct _objc_method);
    }
}

void macho_parse_objc_properties(mach_vm_address_t diff, uint64_t offset, uint64_t n){
    uint64_t off = offset + sizeof(struct _objc_2_class_property_info);
    
    printf("\t\t\tProperties\n");
    
    for(int i=0; i<n; i++){
        struct _objc_2_class_property *property = macho_load_bytes((uint32_t)off,sizeof(struct _objc_2_class_property));
        char *propertyname = macho_read_string((uint64_t)property->name - diff);
        char *attributes = macho_read_string((uint64_t)property->attributes - diff);
        
        printf("\t\t\t\t%s %s\n",attributes,propertyname);
        
        free(property);
        free(propertyname);
        free(attributes);
        off += sizeof(struct _objc_2_class_property);
    }
}

void macho_parse_objc_ivars(mach_vm_address_t diff, uint64_t offset, uint64_t n){
    uint64_t off = offset + sizeof(struct _objc_2_class_ivar_info);
    
    printf("\t\t\tIvars\n");
    
    for(int i=0; i<n; i++){
        struct _objc_ivar *ivar = macho_load_bytes((uint32_t)off,sizeof(struct _objc_2_class_ivar));
        char *ivarname = macho_read_string((uint64_t)ivar->name - diff);
        
        printf("\t\t\t\t0x%08llx: %s\n",ivar->offset,ivarname);
        
        free(ivar);
        free(ivarname);
        off += sizeof(struct _objc_ivar);
    }
}

void macho_parse_objc_class(mach_vm_address_t diff, struct _objc_2_class *class, bool metaclass){
    uint64_t dataptr = (uint64_t)class->data;
    uint64_t dataoff = dataptr - diff;
    
    struct _objc_2_class_data *data = (struct _objc_2_class_data*)macho_load_bytes((uint32_t)dataoff,sizeof(struct _objc_2_class_data));
    
    char *name = macho_read_string(data->name - diff);
    
    if(metaclass)
        printf("\t\t$OBJC_METACLASS_%s\n",name);
    else
        printf("\t\t$OBJC_CLASS_%s\n",name);
    
    uint64_t ivarinfoptr = data->ivars;
    
    if(ivarinfoptr){
        uint64_t ivarinfooff = ivarinfoptr - diff;
        struct _objc_2_class_ivar_info *ivar_info = (struct _objc_2_class_ivar_info*)macho_load_bytes((uint32_t)ivarinfooff,sizeof(struct _objc_2_class_ivar_info));
        uint64_t ivarcount = ivar_info->count;
        
        macho_parse_objc_ivars(diff,ivarinfooff,ivarcount);
        
        free(ivar_info);
    }
    
    uint64_t propertyinfoptr = data->properties;
    
    if(propertyinfoptr){
        uint64_t propertyinfooff = propertyinfoptr - diff;
        struct _objc_2_class_property_info *property_info = (struct _objc_2_class_property_info*)macho_load_bytes((uint32_t)propertyinfooff,sizeof(struct _objc_2_class_property_info));
        uint64_t propertycount = property_info->count;
        
        macho_parse_objc_properties(diff,propertyinfooff,propertycount);
        
        free(property_info);
    }
    
    uint64_t methodinfoptr = data->methods;
    
    if(methodinfoptr){
        uint64_t methodinfooff = methodinfoptr - diff;
        struct _objc_2_class_method_info *method_info = (struct _objc_2_class_method_info*)macho_load_bytes((uint32_t)methodinfooff,sizeof(struct _objc_2_class_method_info));
        
        uint64_t methodcount = method_info->count;
        
        macho_parse_objc_methods(diff,methodinfooff,methodcount,metaclass);
        free(method_info);
    }
    
    free(data);
    free(name);
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
        
        macho_parse_objc_class(diff,class,false);
        
        uint64_t metaclassptr = class->isa;
        uint64_t metaclassoff = metaclassptr - diff;
        struct _objc_2_class *metaclass = (struct _obj_2_class*)macho_load_bytes((uint32_t)metaclassoff,sizeof(struct _objc_2_class));
        
        macho_parse_objc_class(diff,metaclass,true);
        
        
        free(class);
        offset += sizeof(uint64_t);
    }
    
}
