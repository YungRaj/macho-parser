#include <mach-o/swap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include "mach-o.h"
#include "objc.h"

macho_file *gmacho_file = NULL;

typedef struct fat_arch fat_arch_t;
typedef struct fat_header fat_header_t;
typedef struct mach_header mach_header_t;

uint32_t macho_get_magic(uint32_t offset){
    FILE *mach = gmacho_file->file;
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

fat_arch_t macho_get_fat_arch(uint32_t offset){
    FILE *mach = gmacho_file->file;
    fat_arch_t arch;
    fseek(mach, offset, SEEK_SET);
    fread(&arch, sizeof(fat_arch_t), 1, mach);
    return arch;
}

fat_header_t macho_get_fat_header(uint32_t offset){
    FILE *mach = gmacho_file->file;
    fat_header_t header;
    fseek(mach, offset, SEEK_SET);
    fread(&header, sizeof(fat_header_t), 1, mach);
    return header;
}

mach_header_t macho_get_header(uint32_t offset){
    FILE *mach = gmacho_file->file;
    mach_header_t header;
    fseek(mach, offset, SEEK_SET);
    fread(&header, sizeof(mach_header_t), 1, mach);
    return header;
}

void* macho_load_bytes(uint32_t offset, uint32_t size){
    FILE *mach = gmacho_file->file;
    void *buf = calloc(1,size);
    fseek(mach, offset, SEEK_SET);
    fread(buf, size, 1, mach);
    return buf;
}



void macho_print_symtab(mach_header_t header,
                        uint32_t headeroff,
                        uint32_t symoff,
                        uint32_t nsyms,
                        uint32_t stroff,
                        uint32_t strsize){
    if(macho_64bit(header.magic)){
        struct nlist_64 *symtab = macho_load_bytes(symoff + headeroff,sizeof(struct nlist_64) * nsyms);
        
        char *strtab = macho_load_bytes(stroff + headeroff,strsize);
        for(int i=0; i<nsyms; i++){
            struct nlist_64* nl = &symtab[i];
            
            if(nl->n_type & N_STAB) {
                continue;
            }
            
            const char* type = NULL;
            switch(nl->n_type & N_TYPE) {
                case N_UNDF: type = "N_UNDF"; break;
                case N_ABS:  type = "N_ABS"; break;
                case N_SECT: type = "N_SECT"; break;
                case N_PBUD: type = "N_PBUD"; break;
                case N_INDR: type = "N_INDR"; break;
                    
                default:
                    printf("Invalid symbol type: 0x%x\n", nl->n_type & N_TYPE);
                    free(symtab);
                    free(strtab);
                    return;
            }
            
            const char* symname = &strtab[nl->n_un.n_strx];
            printf("\t\tSymbol \"%s\" type: %s value: 0x%llx\n", symname, type, nl->n_value);
        }
        free(symtab);
        free(strtab);
    } else {
        struct nlist *symtab = macho_load_bytes(symoff + headeroff,sizeof(struct nlist) * nsyms);
        char *strtab = macho_load_bytes(stroff + headeroff,strsize);
        for(int i=0; i<nsyms; i++){
            struct nlist* nl = &symtab[i];
            
            if(nl->n_type & N_STAB) {
                continue;
            }
            
            uint32_t value = nl->n_value;
            if((nl->n_type & N_TYPE) == N_SECT && nl->n_desc == N_ARM_THUMB_DEF) {
                value |= 1;
            }
            
            const char* type = NULL;
            switch(nl->n_type & N_TYPE) {
                case N_UNDF: type = "N_UNDF"; break;
                case N_ABS:  type = "N_ABS"; break;
                case N_SECT: type = "N_SECT"; break;
                case N_PBUD: type = "N_PBUD"; break;
                case N_INDR: type = "N_INDR"; break;
                default:
                    printf("Invalid symbol type: 0x%x\n", nl->n_type & N_TYPE);
                    free(symtab);
                    free(strtab);
                    return;
            }
            
            const char* symname = &strtab[nl->n_un.n_strx];
            printf("\t\tSymbol \"%s\" type: %s value: 0x%x\n", symname, type, value);
        }
        free(symtab);
        free(strtab);
    }
}


void macho_parse_code_directory(mach_header_t header, uint32_t headeroff, bool swap, uint32_t offset, uint32_t size){
    SuperBlob *superblob = (SuperBlob*)macho_load_bytes(headeroff + offset,size);
    uint32_t blobcount = swap32(superblob->count);
    
    for(int blob = 0; blob < blobcount; blob++){
        BlobIndex index = superblob->index[blob];
        uint32_t blobtype = swap32(index.type);
        uint32_t bloboffset = swap32(index.offset);
        switch(blobtype){
            case CSSLOT_CODEDIRECTORY:
                ;
                uint32_t begin = headeroff + offset + bloboffset;
                code_directory_t directory = macho_load_bytes(begin, sizeof(struct code_directory));
                uint32_t magic = swap32(directory->blob.magic);
                uint32_t length = swap32(directory->blob.length);
                uint32_t hashOffset = swap32(directory->hashOffset);
                uint32_t identOffset = swap32(directory->identOffset);
                uint32_t nSpecialSlots = swap32(directory->nSpecialSlots);
                uint32_t nCodeSlots = swap32(directory->nCodeSlots);
                uint32_t hashSize = directory->hashSize;
                uint32_t hashType = directory->hashType;
                uint32_t pageSize = directory->pageSize;
                
                if(hashType == HASH_TYPE_SHA1){
                    printf("CD signatures are signed with SHA1\n");
                } else if(hashType == HASH_TYPE_SHA256){
                    printf("CD signatures are signed with SHA256\n");
                } else {
                    printf("Unknown hashing algorithm in pages\n");
                }
                
                for(int i = 0; i < nCodeSlots; i++){
                    uint32_t pages = nCodeSlots;
                    
                    if(pages){
                        printf("\tPage %u ",i);
                    }
                    uint8_t *hash = macho_load_bytes(begin + hashOffset + i * hashSize, hashSize);
                    
                    for(int j = 0; j < hashSize; j++){
                        printf("%.2x",hash[j]);
                    }
                    free(hash);
                    printf("\n");
                }
                break;
            case CSSLOT_INFOSLOT:
                ;
                break;
            case CSSLOT_REQUIREMENTS:
                ;
                break;
            case CSSLOT_RESOURCEDIR:
                ;
                break;
            case CSSLOT_APPLICATION:
                ;
                break;
            case CSSLOT_ENTITLEMENTS:
                ;
                begin = headeroff + offset + bloboffset;
                struct Blob *blob = macho_load_bytes(begin, sizeof(Blob));
                magic = swap32(blob->magic);
                length = swap32(blob->length);
                
                char *entitlements = macho_load_bytes(begin + sizeof(struct Blob), length);
                
                printf("\n\tEntitlements\n");
                printf("%s\n",entitlements);
                
                free(entitlements);
                break;
            default:
                ;
                break;
        }
    }
    free(superblob);
}

void macho_parse_load_commands(mach_header_t header, uint32_t headeroff, bool swap, uint32_t offset, uint32_t ncmds){
    for(int i=0; i<ncmds; i++){
        struct load_command *load_cmd = (struct load_command*)macho_load_bytes(offset,sizeof(struct load_command));
        swap(load_command, load_cmd, swap);
        
        uint32_t cmdtype = load_cmd->cmd;
        uint32_t cmdsize = load_cmd->cmdsize;
        
        switch(cmdtype){
            case LC_SEGMENT:
                ;
                struct segment_command *segment_command = (struct segment_command*)macho_load_bytes(offset,sizeof(struct segment_command));
                swap(segment_command, segment_command, swap);
                uint32_t nsects = segment_command->nsects;
                uint32_t sect_offset = offset + sizeof(struct segment_command);
                printf("LC_SEGMENT - %s 0x%08x to 0x%08x \n",segment_command->segname,
                                                             segment_command->vmaddr,
                                                             segment_command->vmaddr + segment_command->vmsize);
                
                for(int j=1; j<=nsects; j++){
                    struct section *section = (struct section*)macho_load_bytes(sect_offset,sizeof(struct section));
                    printf("\tSection %d: 0x%08x to 0x%08x - %s\n",j,
                                                                   section->addr,
                                                                   section->addr + section->size,
                                                                   section->sectname);
                    
                    sect_offset += sizeof(struct section);
                    free(section);
                }
                free(segment_command);
                break;
            case LC_SEGMENT_64:
                ;
                struct segment_command_64 *segment_command_64 = (struct segment_command_64*)macho_load_bytes(offset,sizeof(struct segment_command_64));
                swap(segment_command_64, segment_command_64, swap);
                nsects = segment_command_64->nsects;
                sect_offset = offset + sizeof(struct segment_command_64);
                printf("LC_SEGMENT_64 - %s 0x%08llx to 0x%08llx \n",segment_command_64->segname,
                                                                segment_command_64->vmaddr,
                                                                segment_command_64->vmaddr + segment_command_64->vmsize);
                
                for(int j=1; j<=nsects; j++){
                    struct section_64 *section = (struct section_64*)macho_load_bytes(sect_offset,sizeof(struct section_64));
                    printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n",j,
                                                               section->addr,
                                                               section->addr + section->size,
                                                               section->sectname);
                    if(strstr("__objc_classlist__DATA",section->sectname)){
                        macho_parse_objc_64(section->addr,headeroff + section->offset,section->size);
                    }
                    
                    sect_offset += sizeof(struct section_64);
                    free(section);
                }
                free(segment_command_64);
                break;
            case LC_LOAD_DYLIB:
                ;
                struct dylib_command *dylib_command = (struct dylib_command*)macho_load_bytes(offset,sizeof(struct dylib_command));
                swap(dylib_command,dylib_command,swap);
                struct dylib dylib = dylib_command->dylib;
                uint32_t dylib_name_offset = offset + dylib.name.offset;
                uint32_t name_len = cmdsize - sizeof(dylib_command);
                char *name = macho_load_bytes(dylib_name_offset,name_len);
                printf("LC_LOAD_DYLIB - %s\n",name);
                printf("\tVers - %u Timestamp - %u\n",dylib.current_version,dylib.timestamp);
                
                free(dylib_command);
                break;
            case LC_SYMTAB:
                ;
                struct symtab_command *symtab_command = (struct symtab_command*)macho_load_bytes(offset,sizeof(struct symtab_command));
                swap(symtab_command,symtab_command,swap);
                printf("LC_SYMTAB\n");
                printf("\tSymbol Table is at offset 0x%x (%u) with %u entries \n",symtab_command->symoff,symtab_command->symoff,symtab_command->nsyms);
                printf("\tString Table is at offset 0x%x (%u) with size of %u bytes\n",symtab_command->stroff,symtab_command->stroff,symtab_command->strsize);
                
                macho_print_symtab(header,
                                   headeroff,
                                   symtab_command->symoff,
                                   symtab_command->nsyms,
                                   symtab_command->stroff,
                                   symtab_command->strsize);
                free(symtab_command);
                break;
            case LC_DYSYMTAB:
                ;
                struct dysymtab_command *dysymtab_command = (struct dysymtab_command*)macho_load_bytes(offset,sizeof(struct dysymtab_command));
                swap(dysymtab_command,dysymtab_command,swap);
                printf("LC_DYSYMTAB\n");
                printf("\t%u local symbols at index %u\n",dysymtab_command->ilocalsym,dysymtab_command->nlocalsym);
                printf("\t%u external symbols at index %u\n",dysymtab_command->nextdefsym,dysymtab_command->iextdefsym);
                printf("\t%u undefined symbols at index %u\n",dysymtab_command->nundefsym,dysymtab_command->iundefsym);
                printf("\t%u Indirect symbols at offset 0x%x\n",dysymtab_command->nindirectsyms,dysymtab_command->indirectsymoff);
                
                free(dysymtab_command);
                break;
            case LC_MAIN:
                ;
                struct entry_point_command *entry_point_command = (struct entry_point_command*)macho_load_bytes(offset,sizeof(struct entry_point_command));
                swap(entry_point_command,entry_point_command,swap);
                printf("LC_MAIN\n");
                printf("\tEntry point at offset 0x%llx\n",entry_point_command->entryoff);
                free(entry_point_command);
                break;
                
            case LC_CODE_SIGNATURE:
                ;
                struct linkedit_data_command *linkedit = (struct linkedit_data_command*)macho_load_bytes(offset,sizeof(struct linkedit_data_command));
                swap(linkedit_data_command,linkedit,swap);
                uint32_t dataoff = linkedit->dataoff;
                uint32_t datasize = linkedit->datasize;
                free(linkedit);
                printf("LC_CODE_SIGNATURE\n");
                macho_parse_code_directory(header, headeroff, swap, dataoff, datasize);
                break;
            default:
                break;
        }
        
        offset += cmdsize;
        
        free(load_cmd);
    }
}

void macho_parse_header(bool swap, uint32_t offset){
    uint32_t magic = macho_get_magic(offset);
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
    
    mach_header_t header = macho_get_header(offset);
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
    macho_parse_load_commands(header, offset, swap, offset + size_header, header.ncmds);
}

void macho_parse_fat_header(bool swap, uint32_t offset){
    fat_header_t header = macho_get_fat_header(0);
    swap(fat_header,&header,swap);
    
    printf("FAT MAGIC %x\n",header.magic);
    
    uint32_t n_fat = header.nfat_arch;
    
    printf("Mach-O image is FAT with %u archs\n",n_fat);
    for(offset = sizeof(fat_header_t);
        offset < sizeof(fat_header_t) + n_fat * sizeof(fat_arch_t);
        offset += sizeof(fat_arch_t)){
        printf("\nImage %d\n\n",(offset-sizeof(fat_header_t))/sizeof(fat_arch_t)+1);
        
        fat_arch_t arch = macho_get_fat_arch(offset);
        swapn(fat_arch,&arch,1,swap);
        
        uint32_t arch_offset = arch.offset;
        macho_parse_header(swap, arch_offset);
    }
}

void macho_parse(FILE *mach, size_t size){
    gmacho_file = malloc(sizeof(macho_file));
    char *buf = malloc(size);
    fseek(mach,0,SEEK_SET);
    fread(buf,1,size,mach);
    gmacho_file->file = mach;
    gmacho_file->buffer = buf;
    gmacho_file->size = size;
    
    
    uint32_t magic = macho_get_magic(0);
    bool swap = macho_swapped(magic);
    
    if(macho_fat(magic)){
        macho_parse_fat_header(swap,0);
    } else {
        macho_parse_header(swap,0);
    }
    
    free(buf);
    free(gmacho_file);
    gmacho_file = NULL;
}
