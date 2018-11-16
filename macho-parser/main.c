#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "mach-o.h"

int main(int argc, const char * argv[]) {
    
    FILE *mach = fopen(argv[1],"rb");
    symbol_table *symbol_table = NULL;
    
    if(!mach){
        printf("File not found\n");
        return 0;
    }
    
    fseek(mach,0,SEEK_END);
    size_t size = ftell(mach);
    fseek(mach,0,SEEK_SET);
    
    if(argc > 2)
    {
        symbol_table = malloc(sizeof(symbol_table));
        
        int argcount = argc - 2;
        symbol_table->symbols = malloc(argcount);
        symbol_table->num_symbols = argcount;
        
        int index = 0;
        
        while(argcount)
        {
            char *symbol = strdup(argv[argcount-- + 1]);
            
            symbol_table->symbols[index++] = symbol;
            
        }
    }
    
    // parse all the load commands, segments, objc metadata, multiple architectures, etc
    macho_parse(mach, argv[1] ,size, symbol_table);
    fclose(mach);
    
    return 0;
}
