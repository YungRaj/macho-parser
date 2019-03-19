#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "parser.h"
#include "mach-o.h"
#include "objc.h"

extern void macho_disassemble_code(mach_vm_address_t offset);

void macho_parse_objc_methods(const char *classname, mach_vm_address_t diff, uint64_t offset, uint64_t n, bool metaclass){
    uint64_t off = offset + sizeof(struct _objc_2_class_method_info);
    
    printf("\t\t\tMethods\n");
    
    for(int i=0; i<n; i++){
        struct _objc_method *method = macho_get_bytes((uint32_t)off);
        char *methodname = macho_read_string((uint64_t)method->name - diff);
        
        bool found = false;
        
        if(gmacho_file->symboltable)
        {
            char **symbols = gmacho_file->symboltable->symbols;
            uint32_t num_symbols = gmacho_file->symboltable->num_symbols;
            
            for(int j=0; j<num_symbols; j++)
            {
                char *symbolclassname;
                char *symbolmethodname;
                
                char *symbol = strdup(symbols[j]);
                
                char **res = NULL;
                uint32_t num_tokens = 0;
                
                char *tmp = NULL;
                
                tmp = strtok(symbol, "-");
                
                while (tmp) {
                    
                    res = realloc (res, sizeof (char*) * ++num_tokens);
                    
                    if (res == NULL)
                        break;
                    
                    res[num_tokens-1] = tmp;
                    
                    tmp = strtok (NULL, "-");
                    
                }
                
                if(num_tokens == 2)
                {
                    symbolclassname = res[0];
                    symbolmethodname = res[1];
                    
                    if(strcmp(classname,symbolclassname) == 0 &&
                       strcmp(methodname,symbolmethodname) == 0)
                    {
                        found = true;
                    }
                }
            }
        }
        
        if(metaclass)
            printf("\t\t\t\t0x%08llx: +%s\n",method->offset,methodname);
        else
            printf("\t\t\t\t0x%08llx: -%s\n",method->offset,methodname);
        
        if(found)
            macho_disassemble_code(method->offset);
        
        off += sizeof(struct _objc_method);
    }
}

void macho_parse_objc_properties(const char *classname, mach_vm_address_t diff, uint64_t offset, uint64_t n){
    uint64_t off = offset + sizeof(struct _objc_2_class_property_info);
    
    printf("\t\t\tProperties\n");
    
    for(int i=0; i<n; i++){
        struct _objc_2_class_property *property = macho_get_bytes((uint32_t)off);
        char *propertyname = macho_read_string((uint64_t)property->name - diff);
        char *attributes = macho_read_string((uint64_t)property->attributes - diff);
        
        printf("\t\t\t\t%s %s\n",attributes,propertyname);
        
        off += sizeof(struct _objc_2_class_property);
    }
}

void macho_parse_objc_ivars(const char *classname, mach_vm_address_t diff, uint64_t offset, uint64_t n){
    uint64_t off = offset + sizeof(struct _objc_2_class_ivar_info);
    
    printf("\t\t\tIvars\n");
    
    for(int i=0; i<n; i++){
        struct _objc_ivar *ivar = macho_get_bytes((uint32_t)off);
        char *ivarname = macho_read_string((uint64_t)ivar->name - diff);
        
        printf("\t\t\t\t0x%08llx: %s\n",ivar->offset,ivarname);
        
        off += sizeof(struct _objc_ivar);
    }
}

void macho_parse_objc_class(mach_vm_address_t diff, struct _objc_2_class *class, bool metaclass){
    uint64_t dataptr = (uint64_t)class->data;
    uint64_t dataoff = dataptr - diff;
    
    struct _objc_2_class_data *data = (struct _objc_2_class_data*)macho_get_bytes((uint32_t)dataoff);
    
    char *name = macho_read_string(data->name - diff);
    
    if(metaclass)
        printf("\t\t$OBJC_METACLASS_%s\n",name);
    else
        printf("\t\t$OBJC_CLASS_%s\n",name);
    
    uint64_t ivarinfoptr = data->ivars;
    
    if(ivarinfoptr){
        uint64_t ivarinfooff = ivarinfoptr - diff;
        struct _objc_2_class_ivar_info *ivar_info = (struct _objc_2_class_ivar_info*)macho_get_bytes((uint32_t)ivarinfooff);
        uint64_t ivarcount = ivar_info->count;
        
        macho_parse_objc_ivars(name,diff,ivarinfooff,ivarcount);
    }
    
    uint64_t propertyinfoptr = data->properties;
    
    if(propertyinfoptr){
        uint64_t propertyinfooff = propertyinfoptr - diff;
        struct _objc_2_class_property_info *property_info = (struct _objc_2_class_property_info*)macho_get_bytes((uint32_t)propertyinfooff);
        uint64_t propertycount = property_info->count;
        
        macho_parse_objc_properties(name,diff,propertyinfooff,propertycount);
    }
    
    uint64_t methodinfoptr = data->methods;
    
    if(methodinfoptr){
        uint64_t methodinfooff = methodinfoptr - diff;
        struct _objc_2_class_method_info *method_info = (struct _objc_2_class_method_info*)macho_get_bytes((uint32_t)methodinfooff);
        
        uint64_t methodcount = method_info->count;
        
        macho_parse_objc_methods(name,diff,methodinfooff,methodcount,metaclass);
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
        
        struct _objc_2_class *class = (struct _objc_2_class*)macho_get_bytes((uint32_t)classoff);
        
        macho_parse_objc_class(diff,class,false);
        
        uint64_t metaclassptr = class->isa;
        uint64_t metaclassoff = metaclassptr - diff;
        struct _objc_2_class *metaclass = (struct _obj_2_class*)macho_get_bytes((uint32_t)metaclassoff);
        
        macho_parse_objc_class(diff,metaclass,true);
        
        offset += sizeof(uint64_t);
    }
    
}
