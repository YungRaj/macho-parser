#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "mach-o.h"

int main(int argc, const char * argv[]) {
    FILE *mach = fopen(argv[1],"rb");
    
    if(!mach){
        printf("File not found\n");
        return 0;
    }
    
    fseek(mach,0,SEEK_END);
    size_t size = ftell(mach);
    fseek(mach,0,SEEK_SET);
    
    // parse all the load commands, segments, objc metadata, multiple architectures, etc
    macho_parse(mach, argv[1] ,size);
    fclose(mach);
    
    return 0;
}
