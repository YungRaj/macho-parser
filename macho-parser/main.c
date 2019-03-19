#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "mach-o.h"

int main(int argc, const char * argv[]) {
    // arg 1 -> name of file to be processed, expectedly a macho file
    // arg 1 + n -> name of a symbol to be processed/disassembled
    // if symbol is found in objc metadata specify by using CLASSNAME-METHOD
    
    FILE *mach = fopen(argv[1],"rb");
    // symbol table is list of symbols to be disassembled
    symbol_table *symbol_table = NULL;
    
    if(!mach){
        printf("File not found\n");
        return 0;
    }
    
    fseek(mach,0,SEEK_END);
    size_t size = ftell(mach);
    fseek(mach,0,SEEK_SET);
    
    // populate the list if the number of arguments is greater than 1
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
