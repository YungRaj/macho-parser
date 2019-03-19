#include <mach-o/swap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <CommonCrypto/CommonDigest.h>
#include "mach-o.h"
#include "objc.h"

#include <capstone/capstone.h>

/* todo list, don't manually load each byte needed onto the heap, just use universal buffer */

macho_file *gmacho_file = NULL;

typedef struct fat_arch fat_arch_t;
typedef struct fat_header fat_header_t;
typedef struct mach_header mach_header_t;

macho_file* get_macho()
{
    return gmacho_file;
}

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

void macho_disassemble_code(mach_vm_address_t offset)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    const uint8_t *code_buffer;
    
    if(offset > gmacho_file->size)
        offset -= 0x100000000;
    
    if(offset > gmacho_file->size)
        return;
    
    code_buffer = (const uint8_t*)(gmacho_file->buffer + offset);
    
    if ( gmacho_file->x86 && gmacho_file->is64bit ){
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return;
    }
    else if ( gmacho_file->arm && gmacho_file->is64bit){
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
            return;
    } else
        return;
    // we only care about 64 bit binaries that either are arm or x86
    // capstone does the rest of the work by providing the inline disassembly
        
    
    count = cs_disasm(handle, code_buffer, 0x100, 0x1000, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("\t\t\t\t\t0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
        }
        
        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");
    
    cs_close(&handle);
    
}



void macho_print_symtab(mach_header_t header,
                        uint32_t headeroff,
                        uint32_t symoff,
                        uint32_t nsyms,
                        uint32_t stroff,
                        uint32_t strsize){
    if(macho_64bit(header.magic)){
        struct nlist_64 *symtab = macho_get_bytes(symoff + headeroff);
        
        char *strtab = macho_get_bytes(stroff + headeroff);
        for(int i=0; i<nsyms; i++){
            struct nlist_64* nl = &symtab[i];
            
            if(nl->n_type & N_STAB) {
                continue;
            }
            
            bool found = false;
            const char* type = NULL;
            const char* symname = &strtab[nl->n_un.n_strx];
            
            switch(nl->n_type & N_TYPE) {
                case N_UNDF: type = "N_UNDF"; break;
                case N_ABS:  type = "N_ABS"; break;
                case N_SECT: type = "N_SECT";
                    
                    // this symbol table is provided by the user to disassemble any symbols found
                    // find the symbol here
                    if(gmacho_file->symboltable)
                    {
                        char **symbols = gmacho_file->symboltable->symbols;
                        uint32_t num_symbols = gmacho_file->symboltable->num_symbols;
                        
                        for(int j=0; j<num_symbols; j++)
                        {
                            char *symbol = symbols[j];
                            
                            if(strcmp(symname,symbol) == 0)
                            {
                                found = true;
                            }
                        }
                    }
                    
                    break;
                case N_PBUD: type = "N_PBUD"; break;
                case N_INDR: type = "N_INDR"; break;
                    
                default:
                    printf("Invalid symbol type: 0x%x\n", nl->n_type & N_TYPE);
                    return;
            }
            
            printf("\t\tSymbol \"%s\" type: %s value: 0x%llx\n", symname, type, nl->n_value);
            
            if(found)
               macho_disassemble_code(nl->n_value);
        }
    } else {
        struct nlist *symtab = macho_get_bytes(symoff + headeroff);
        char *strtab = macho_get_bytes(stroff + headeroff);
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
            const char* symname = &strtab[nl->n_un.n_strx];
            
            switch(nl->n_type & N_TYPE) {
                case N_UNDF: type = "N_UNDF"; break;
                case N_ABS:  type = "N_ABS";  break;
                case N_SECT: type = "N_SECT";
                    
                    // this symbol table is provided by the user to disassemble any symbols found
                    // find the symbol here
                    if(gmacho_file->symboltable)
                    {
                        char **symbols = gmacho_file->symboltable->symbols;
                        uint32_t num_symbols = gmacho_file->symboltable->num_symbols;
                        
                        for(int j=0; j<num_symbols; j++)
                        {
                            char *symbol = symbols[j];
                            
                            if(strcmp(symname,symbol) == 0)
                            {
                                
                            }
                        }
                    }
                    
                    break;
                case N_PBUD: type = "N_PBUD"; break;
                case N_INDR: type = "N_INDR"; break;
                default:
                    printf("Invalid symbol type: 0x%x\n", nl->n_type & N_TYPE);
                    return;
            }
            
            printf("\t\tSymbol \"%s\" type: %s value: 0x%x\n", symname, type, value);
        }
    }
}

void macho_parse_linkedit(mach_vm_address_t addr, uint64_t offset, uint64_t size)
{
    // todo list rebasing opcodes, binding info, exports, function starts, data in code, etc
    // this is something i don't know how to do yet as it is not documented well
    // might not ever get to this, because it's hard
}

enum
{
    ENTITLEMENTS,
    APPLICATION_SPECIFIC,
    RESOURCE_DIR,
    REQUIREMENTS_BLOB,
    BOUND_INFO_PLIST
};

typedef struct{
    char *name;
    uint8_t *data;
    uint8_t *hash;
    uint32_t hashSize;
    bool sha256;
} special_slot;

static special_slot specialSlots[5] = {{"Entitlements.plist", NULL, NULL },
                                        {"Application Specific",NULL, NULL},
                                        { "Resource Directory", NULL, NULL},
                                        {"Requirements Blob", NULL, NULL},
                                        {"Bound Info.plist", NULL, NULL}
};

#define min(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })

bool macho_compare_hash(uint8_t *hash1, uint8_t *hash2, uint32_t hashSize)
{
    return (memcmp(hash1, hash2, hashSize) == 0);
}

uint8_t* macho_compute_hash(bool sha256, uint8_t *blob, uint32_t size)
{
    uint8_t *result;
    
    if(sha256)
    {
        result = malloc(CC_SHA256_DIGEST_LENGTH);
        CC_SHA256(blob, size, result);
    } else
    {
        result = malloc(CC_SHA1_DIGEST_LENGTH);
        CC_SHA1(blob, size, result);
    }
    
    return result;
}

bool macho_verify_code_slot(bool sha256, char *signature, uint32_t signature_size, uint32_t offset, uint32_t size)
{
    bool verified = false;
    
    uint8_t *blob = (uint8_t*)macho_get_bytes(offset);
    
    if(sha256)
    {
        unsigned char result[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(blob, size, result);
     
        verified = (memcmp(result,signature,min(CC_SHA256_DIGEST_LENGTH,signature_size)) == 0);
        
        assert(CC_SHA256_DIGEST_LENGTH == signature_size);
    } else {
        unsigned char result[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(blob, size, result);
        
        verified = (memcmp(result,signature,min(CC_SHA1_DIGEST_LENGTH,signature_size)) == 0);
        
        assert(CC_SHA1_DIGEST_LENGTH == signature_size);
    }
    
    return verified;
}


void macho_parse_code_directory(mach_header_t header, uint32_t headeroff, bool swap, uint32_t offset, uint32_t size)
{
    SuperBlob *superblob = (SuperBlob*)macho_get_bytes(headeroff + offset);
    uint32_t blobcount = swap32(superblob->count);
    
    printf("%u blobs\n",blobcount);
    
    for(int blob = 0; blob < blobcount; blob++){
        BlobIndex index = superblob->index[blob];
        uint32_t blobtype = swap32(index.type);
        uint32_t bloboffset = swap32(index.offset);
        uint32_t begin = headeroff + offset + bloboffset;
        
        Blob *blob = macho_get_bytes(begin);
        uint32_t magic = swap32(blob->magic);
        uint32_t length = swap32(blob->length);
        
        switch(magic){
            case CSMAGIC_CODEDIRECTORY:
                ;
                code_directory_t directory = macho_get_bytes(begin);
                uint32_t hashOffset = swap32(directory->hashOffset);
                uint32_t identOffset = swap32(directory->identOffset);
                uint32_t nSpecialSlots = swap32(directory->nSpecialSlots);
                uint32_t nCodeSlots = swap32(directory->nCodeSlots);
                uint32_t hashSize = directory->hashSize;
                uint32_t hashType = directory->hashType;
                uint32_t pageSize = directory->pageSize;
                bool sha256 = false;
                
                char *ident = macho_read_string(begin + identOffset);
                printf("Identifier: %s\n",ident);
                printf("Page size: %u bytes\n",1 << pageSize);
                
                if(hashType == HASH_TYPE_SHA1){
                    printf("CD signatures are signed with SHA1\n");
                } else if(hashType == HASH_TYPE_SHA256){
                    sha256 = true;
                    printf("CD signatures are signed with SHA256\n");
                } else {
                    printf("Unknown hashing algorithm in pages\n");
                }
                
                for(int i = 0; i < nCodeSlots; i++){
                    uint32_t pages = nCodeSlots;
                    
                    if(pages){
                        printf("\tPage %2u ",i);
                    }
                    uint8_t *hash = macho_get_bytes(begin + hashOffset + i * hashSize);
                    
                    for(int j = 0; j < hashSize; j++){
                        printf("%.2x",hash[j]);
                    }
                    
                    if(i + 1 != nCodeSlots)
                    {
                        if(macho_verify_code_slot(sha256,(char*)hash,hashSize,headeroff + i * (1 << pageSize), 1 << pageSize))
                            printf(" OK...");
                        else
                            printf(" Invalid!!!");
                    } else {
                        if(macho_verify_code_slot(sha256,
                                                  (char*)hash,
                                                  hashSize,
                                                  headeroff + i * (1 << pageSize),
                                                  (headeroff + offset) % (1 << pageSize)))
                        // hash the last page only until the code signature,
                        // so that that code signature doesn't get included into hash
                            printf(" OK...");
                    }
                    
                    printf("\n");
                }
                
                begin = headeroff + offset + bloboffset - hashSize * nSpecialSlots;
                
                printf("\nSpecial Slots\n");
                
                for(int i = 0; i < nSpecialSlots; i++){
                    
                    if(i<5)
                        printf("\t%s ",specialSlots[i].name);
                    
                    uint8_t *hash = macho_get_bytes(begin + hashOffset + i * hashSize);
                    
                    for(int j = 0; j < hashSize; j++){
                        printf("%.2x",hash[j]);
                    }
                    
                    
                    specialSlots[i].sha256 = (hashType == HASH_TYPE_SHA256);
                    specialSlots[i].hash = hash;
                    specialSlots[i].hashSize = hashSize;
                    
                    uint8_t *zero_buffer = calloc(hashSize, sizeof(uint8_t));
                    
                    if(memcmp(hash, zero_buffer, hashSize) != 0)
                    {
                        if(i == BOUND_INFO_PLIST)
                        {
                            char *path = get_macho()->path;
                            
                            char **res = NULL;
                            bool found = false;
                            uint32_t num_tokens = 0;
                            uint32_t new_length = 0;
                            
                            char *app_dir = strtok(path, "/");
                            
                            while (app_dir) {
                                new_length += strlen(app_dir);
                                
                                res = realloc (res, sizeof (char*) * ++num_tokens);
                                
                                if (res == NULL)
                                    break;
                                
                                res[num_tokens-1] = app_dir;
                                
                                app_dir = strtok (NULL, "/");
                                
                                if(strcmp(app_dir,"MacOS") == 0)
                                {
                                    found = true;
                                    break;
                                }
                                
                            }
                            
                            if(!found)
                                continue;
                            
                            new_length += num_tokens + 1;
                            
                            char *info_plist = malloc(sizeof(char) * new_length);
                            
                            for(int j=0; j < num_tokens; j++)
                            {
                                strcat(info_plist,"/");
                                strcat(info_plist,res[j]);
                            }
                            
                            strcat(info_plist,"/Info.plist");
                            
                            FILE *info = fopen(info_plist, "rb");
                            fseek(info,0,SEEK_END);
                            size_t info_size = ftell(info);
                            fseek(info,0,SEEK_SET);
                            
                            uint8_t *info_buf = malloc(info_size);
                            fseek(info,0,SEEK_SET);
                            fread(info_buf,1,size,info);
                            
                            fclose(info);
                            
                            uint8_t *info_hash = macho_compute_hash(specialSlots[i].sha256, info_buf, (uint32_t)info_size);
                            
                            if(memcmp(info_hash, specialSlots[i].hash, specialSlots[i].hashSize) == 0)
                                printf(" OK...");
                            else
                                printf(" Invalid!!!");
                        
                            
                        }
                        
                        free(zero_buffer);
                                                      
                    }
                                                  
                    
                    printf("\n");
                }
                break;
            case CSMAGIC_BLOBWRAPPER:
                ;
                break;
            case CSMAGIC_REQUIREMENTS:
                ;
                break;
            case CSMAGIC_EMBEDDED_ENTITLEMENTS:
                ;
                uint8_t *blob_raw;
                uint8_t *blob_hash;
                
                char *entitlements;
                
                entitlements = malloc(length - sizeof(struct Blob));
                memcpy(entitlements, macho_get_bytes(begin + sizeof(struct Blob)), length - sizeof(struct Blob));
                
                blob_raw = macho_get_bytes(begin);
                blob_hash = macho_compute_hash(specialSlots[ENTITLEMENTS].sha256, blob_raw, length);
                
                printf("\nEntitlements ");
                
                if(macho_compare_hash(specialSlots[ENTITLEMENTS].hash, blob_hash, specialSlots[ENTITLEMENTS].hashSize))
                    printf("OK...\n");
                else
                    printf("Invalid!!!\n");
                
                printf("%s\n",entitlements);
                
                free(entitlements);
                
                break;
            default:
                ;
                break;
        }
    }
}

void macho_parse_load_commands(mach_header_t header, uint32_t headeroff, bool swap, uint32_t offset, uint32_t ncmds){
    for(int i=0; i<ncmds; i++){
        struct load_command *load_cmd = (struct load_command*)macho_get_bytes(offset);
        swap(load_command, load_cmd, swap);
        
        uint32_t cmdtype = load_cmd->cmd;
        uint32_t cmdsize = load_cmd->cmdsize;
        
        switch(cmdtype){
            case LC_SEGMENT:
                ;
                struct segment_command *segment_command = (struct segment_command*)macho_get_bytes(offset);
                swap(segment_command, segment_command, swap);
                uint32_t nsects = segment_command->nsects;
                uint32_t sect_offset = offset + sizeof(struct segment_command);
                printf("LC_SEGMENT - %s 0x%08x to 0x%08x \n",segment_command->segname,
                                                             segment_command->vmaddr,
                                                             segment_command->vmaddr + segment_command->vmsize);
                
                for(int j=1; j<=nsects; j++){
                    struct section *section = (struct section*)macho_get_bytes(sect_offset);
                    printf("\tSection %d: 0x%08x to 0x%08x - %s\n",j,
                                                                   section->addr,
                                                                   section->addr + section->size,
                                                                   section->sectname);
                    
                    sect_offset += sizeof(struct section);
                }
                break;
            case LC_SEGMENT_64:
                ;
                struct segment_command_64 *segment_command_64 = (struct segment_command_64*)macho_get_bytes(offset);
                swap(segment_command_64, segment_command_64, swap);
                nsects = segment_command_64->nsects;
                sect_offset = offset + sizeof(struct segment_command_64);
                printf("LC_SEGMENT_64 - %s 0x%08llx to 0x%08llx \n",segment_command_64->segname,
                                                                segment_command_64->vmaddr,
                                                                segment_command_64->vmaddr + segment_command_64->vmsize);
                
                for(int j=1; j<=nsects; j++){
                    struct section_64 *section = (struct section_64*)macho_get_bytes(sect_offset);
                    printf("\tSection %d: 0x%08llx to 0x%08llx - %s\n",j,
                                                               section->addr,
                                                               section->addr + section->size,
                                                               section->sectname);
                    if(strstr("__objc_classlist__DATA",section->sectname)){
                        macho_parse_objc_64(section->addr,headeroff + section->offset,section->size);
                    }
                    
                    if(strstr("__LINKEDIT",section->sectname))
                    {
                        // manually look for the LINKEDIT segment so that we can parse information not covered by load commands
                        // probably a better way to do this semantically but for now this is fine
                        // don't cover the indirect/direct symbol tables, code signature etc because those are covered by lc's
                        macho_parse_linkedit(section->addr,headeroff + section->offset, section->size);
                    }
                    
                    sect_offset += sizeof(struct section_64);
                }
                
                break;
            case LC_LOAD_DYLIB:
                ;
                struct dylib_command *dylib_command = (struct dylib_command*)macho_get_bytes(offset);
                swap(dylib_command,dylib_command,swap);
                struct dylib dylib = dylib_command->dylib;
                uint32_t dylib_name_offset = offset + dylib.name.offset;
                uint32_t name_len = cmdsize - sizeof(dylib_command);
                char *name = macho_get_bytes(dylib_name_offset);
                printf("LC_LOAD_DYLIB - %s\n",name);
                printf("\tVers - %u Timestamp - %u\n",dylib.current_version,dylib.timestamp);
                
                break;
            case LC_SYMTAB:
                ;
                struct symtab_command *symtab_command = (struct symtab_command*)macho_get_bytes(offset);
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
                break;
            case LC_DYSYMTAB:
                ;
                struct dysymtab_command *dysymtab_command = (struct dysymtab_command*)macho_get_bytes(offset);
                swap(dysymtab_command,dysymtab_command,swap);
                printf("LC_DYSYMTAB\n");
                printf("\t%u local symbols at index %u\n",dysymtab_command->ilocalsym,dysymtab_command->nlocalsym);
                printf("\t%u external symbols at index %u\n",dysymtab_command->nextdefsym,dysymtab_command->iextdefsym);
                printf("\t%u undefined symbols at index %u\n",dysymtab_command->nundefsym,dysymtab_command->iundefsym);
                printf("\t%u Indirect symbols at offset 0x%x\n",dysymtab_command->nindirectsyms,dysymtab_command->indirectsymoff);
                break;
            case LC_MAIN:
                ;
                struct entry_point_command *entry_point_command = (struct entry_point_command*)macho_get_bytes(offset);
                swap(entry_point_command,entry_point_command,swap);
                printf("LC_MAIN\n");
                printf("\tEntry point at offset 0x%llx\n",entry_point_command->entryoff);
                break;
                
            case LC_CODE_SIGNATURE:
                ;
                // looks weird at first, but the code signature load command refers the linkedit_data_command structure
                // the code signature still points to the code signature and not the LINKEDIT segment
                // because the code signature is at the end of the linkedit segment
                // code signatures are going to always be at the end of the file because they can change based on who signs it
                struct linkedit_data_command *linkedit = (struct linkedit_data_command*)macho_get_bytes(offset);
                swap(linkedit_data_command,linkedit,swap);
                uint32_t dataoff = linkedit->dataoff;
                uint32_t datasize = linkedit->datasize;
                
                printf("LC_CODE_SIGNATURE\n");
                macho_parse_code_directory(header, headeroff, swap, dataoff, datasize);
                break;
            default:
                break;
        }
        
        offset += cmdsize;
    }
}

void macho_parse_header(bool swap, uint32_t offset){
    uint32_t magic = macho_get_magic(offset);
    swap = macho_swapped(magic);
    
    printf("MACH MAGIC - %x\n",magic);
    
    if(macho_64bit(magic)){
        printf("Mach-O image is 64 bit\n");
        
        gmacho_file->is64bit = true;
        
    } else if(macho_valid(magic)) {
        printf("Mach-O image is 32 bit\n");
    } else {
        printf("Invalid Mach-O Magic, exiting...\n");
        return;
    }
    
    mach_header_t header = macho_get_header(offset);
    swap(mach_header,&header,swap);
    
    cpu_type_t cpu_type = header.cputype;
    
    if(cpu_type == CPU_TYPE_X86_64)
        gmacho_file->x86 = true;
    if(cpu_type == CPU_TYPE_ARM)
        gmacho_file->arm = true;
    if(cpu_type == CPU_TYPE_ARM64)
        gmacho_file->arm = true;
    
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
    
    gmacho_file->fat = true;
    
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

void macho_parse(FILE *mach, char *path, size_t size, symbol_table *symbols){
    gmacho_file = malloc(sizeof(macho_file));
    char *buf = malloc(size);
    fseek(mach,0,SEEK_SET);
    fread(buf,1,size,mach);
    gmacho_file->path = path;
    gmacho_file->file = mach;
    gmacho_file->buffer = buf;
    gmacho_file->size = size;
    gmacho_file->symboltable = symbols;
    
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
