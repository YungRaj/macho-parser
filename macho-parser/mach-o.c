#include "mach-o.h"
#include <mach-o/swap.h>

#define swap(x,y,s) if(s) swap_ ## x(y,NXHostByteOrder())
#define swapn(x,y,n,s) if(s) swap_ ## x(y,n,NXHostByteOrder())

typedef struct fat_arch fat_arch_t;
typedef struct fat_header fat_header_t;
typedef struct mach_header mach_header_t;

typedef struct{
    char *buffer;
    size_t size;
} macho_file;

uint32_t macho_get_magic(FILE *mach, uint32_t offset){
    uint32_t magic;
    fseek(mach, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, mach);
    return magic;
}

bool macho_fat(uint32_t magic){
    return magic == FAT_CIGAM || magic == FAT_MAGIC;
}

bool macho_32bit(uint32_t magic){
    return magic == MH_MAGIC || magic == MH_CIGAM;
}

bool macho_64bit(uint32_t magic){
    return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

bool macho_valid(uint32_t magic){
    return macho_fat(magic) || macho_32bit(magic) || macho_64bit(magic);
}

bool macho_swapped(uint32_t magic){
    return magic == MH_CIGAM || magic == MH_CIGAM_64 || magic == FAT_CIGAM;
}

fat_arch_t macho_get_fat_arch(FILE *mach, uint32_t offset){
    fat_arch_t arch;
    fseek(mach, offset, SEEK_SET);
    fread(&arch, sizeof(fat_arch_t), 1, mach);
    return arch;
}

fat_header_t macho_get_fat_header(FILE *mach, uint32_t offset){
    fat_header_t header;
    fseek(mach, offset, SEEK_SET);
    fread(&header, sizeof(fat_header_t), 1, mach);
    return header;
}

mach_header_t macho_get_header(FILE *mach, uint32_t offset){
    mach_header_t header;
    fseek(mach, offset, SEEK_SET);
    fread(&header, sizeof(mach_header_t), 1, mach);
    return header;
}

void* macho_load_bytes(FILE *mach, uint32_t offset, uint32_t size){
    void *buf = calloc(1,size);
    fseek(mach, offset, SEEK_SET);
    fread(buf, size, 1, mach);
    return buf;
}

void macho_parse_load_commands(FILE *mach, bool swap, uint32_t offset, uint32_t ncmds){
    
    for(int i=0; i<ncmds; i++){
        struct load_command *load_cmd = (struct load_command*)macho_load_bytes(mach,offset,sizeof(struct load_command));
        swap(load_command, load_cmd, swap);
        
        uint32_t cmdtype = load_cmd->cmd;
        uint32_t cmdsize = load_cmd->cmdsize;
        
        switch(cmdtype){
            case LC_SEGMENT:
                ;
                struct segment_command *segment_command = (struct segment_command*)macho_load_bytes(mach,offset,sizeof(struct segment_command));
                swap(segment_command, segment_command, swap);
                uint32_t nsects = segment_command->nsects;
                uint32_t sect_offset = offset + sizeof(struct segment_command);
                printf("LC_SEGMENT - %s\n",segment_command->segname);
                
                for(int j=1; j<=nsects; j++){
                    struct section *section = (struct section*)macho_load_bytes(mach,sect_offset,sizeof(struct section));
                    printf("Section %d - %s\n",j,section->sectname);
                    sect_offset += sizeof(struct section);
                    free(section);
                }
                free(segment_command);
                break;
            case LC_SEGMENT_64:
                ;
                struct segment_command_64 *segment_command_64 = (struct segment_command_64*)macho_load_bytes(mach,offset,sizeof(struct segment_command_64));
                swap(segment_command_64, segment_command_64, swap);
                nsects = segment_command_64->nsects;
                sect_offset = offset + sizeof(struct segment_command_64);
                printf("LC_SEGMENT_64 - %s\n",segment_command_64->segname);
                
                for(int j=1; j<=nsects; j++){
                    struct section_64 *section = (struct section_64*)macho_load_bytes(mach,sect_offset,sizeof(struct section_64));
                    printf("\tSection %d - %s\n",j,section->sectname);
                    sect_offset += sizeof(struct section_64);
                    free(section);
                }
                free(segment_command_64);
                break;
            case LC_LOAD_DYLIB:
                ;
                struct dylib_command *dylib_command = (struct dylib_command*)macho_load_bytes(mach,offset,sizeof(dylib_command));
                swap(dylib_command,dylib_command,swap);
                struct dylib dylib = dylib_command->dylib;
                uint32_t dylib_name_offset = offset + sizeof(struct dylib_command) + dylib.name.offset;
                uint32_t name_len = cmdsize - sizeof(dylib_command);
                char *name = macho_load_bytes(mach,dylib_name_offset,name_len);
                printf("LC_LOAD_DYLIB - %s\n",name);
                printf("\tVers - %u Timestamp - %u\n",dylib.current_version,dylib.timestamp);
                
                free(dylib_command);
            default:
                break;
        }
        
        offset += cmdsize;
        
        free(load_cmd);
    }
}

void macho_parse_header(FILE *mach, bool swap, uint32_t offset){
    uint32_t magic = macho_get_magic(mach,offset);
    swap = macho_swapped(magic);
    
    printf("MACH MAGIC - %x\n",magic);
    
    if(macho_64bit(magic)){
        printf("Mach-O image is 64 bit\n");
    } else if(macho_valid(magic)) {
        printf("Mach-O image is 32 bit\n");
    } else {
        printf("Invalid Mach-O Magic, exiting...\n");
        return;
    }
    
    mach_header_t header = macho_get_header(mach,offset);
    swap(mach_header,&header,swap);
    
    cpu_type_t cpu_type = header.cputype;
    
    for(int i=0; i<NUM_CPUS; i++){
        struct cpu_type_names cpu = cpu_type_names[i];
        if(cpu_type == cpu.cputype){
            printf("CPU - %s\n",cpu.cpu_name);
            break;
        }
    }
    
    int size_header = macho_64bit(magic) ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    macho_parse_load_commands(mach, swap, offset + size_header, header.ncmds);
}

void macho_parse_fat_header(FILE *mach, bool swap, uint32_t offset){
    fat_header_t header = macho_get_fat_header(mach,0);
    swap(fat_header,&header,swap);
    
    printf("FAT MAGIC %x\n",header.magic);
    
    uint32_t n_fat = header.nfat_arch;
    
    printf("Mach-O image is FAT with %u archs\n",n_fat);
    for(offset = sizeof(fat_header_t);
        offset < sizeof(fat_header_t) + n_fat * sizeof(fat_arch_t);
        offset += sizeof(fat_arch_t)){
        printf("\nImage %d\n\n",(offset-sizeof(fat_header_t))/sizeof(fat_arch_t)+1);
        
        fat_arch_t arch = macho_get_fat_arch(mach, offset);
        swapn(fat_arch,&arch,1,swap);
        
        uint32_t arch_offset = arch.offset;
        macho_parse_header(mach, swap, arch_offset);
    }
}

void macho_parse(FILE *mach, size_t size){
    macho_file *file = malloc(sizeof(macho_file));
    char *buf = malloc(size);
    fread(buf,1,size,mach);
    file->buffer = buf;
    file->size = size;
    
    uint32_t magic = macho_get_magic(mach,0);
    bool swap = macho_swapped(magic);
    
    if(macho_fat(magic)){
        macho_parse_fat_header(mach, swap,0);
    } else {
        macho_parse_header(mach, swap,0);
    }
    
    free(buf);
    free(file);
}
