#include <mach-o/loader.h>
#include "parser.h"

#ifndef __macho_h
#define __macho_h

typedef int integer_t;
typedef integer_t    cpu_type_t;
typedef integer_t    cpu_subtype_t;
typedef int        vm_prot_t;


struct cpu_type_names {
    cpu_type_t cputype;
    const char* cpu_name;
};

#define NUM_CPUS 4

static struct cpu_type_names cpu_type_names[] = {
    {CPU_TYPE_I386,        "i386"},
    {CPU_TYPE_X86_64,    "x86_64"},
    {CPU_TYPE_ARM,        "arm"},
    {CPU_TYPE_ARM64,    "arm64"}
};

#define CSMAGIC_REQUIREMENT            0xfade0c00
#define CSMAGIC_REQUIREMENTS           0xfade0c01
#define CSMAGIC_CODEDIRECTORY          0xfade0c02
#define CSMAGIC_EMBEDDED_SIGNATURE     0xfade0cc0
#define CSMAGIC_EMBEDDED_SIGNATURE_OLD 0xfade0b02
#define CSMAGIC_EMBEDDED_ENTITLEMENTS  0xfade7171
#define CSMAGIC_DETACHED_SIGNATURE     0xfade0cc1
#define CSMAGIC_BLOBWRAPPER            0xfade0b01

#define CSSLOT_CODEDIRECTORY 0x00000
#define CSSLOT_INFOSLOT      0x00001
#define CSSLOT_REQUIREMENTS  0x00002
#define CSSLOT_RESOURCEDIR   0x00003
#define CSSLOT_APPLICATION   0x00004
#define CSSLOT_ENTITLEMENTS  0x00005

#define CSSLOT_SIGNATURESLOT 0x10000

#define HASH_TYPE_SHA1 0x01
#define HASH_TYPE_SHA256 0x02

typedef struct{
    uint32_t type;
    uint32_t offset;
} BlobIndex ;

typedef struct Blob {
    uint32_t magic;
    uint32_t length;
} Blob;

typedef struct {
    Blob blob;
    uint32_t count;
    BlobIndex index[];
} SuperBlob;

typedef struct code_directory {
    struct Blob blob;
    uint32_t version;       /* compatibility version */
    uint32_t flags;         /* setup and mode flags */
    uint32_t hashOffset;      /* offset of hash slot element at index zero */
    uint32_t identOffset;     /* offset of identifier string */
    uint32_t nSpecialSlots;     /* number of special hash slots */
    uint32_t nCodeSlots;      /* number of ordinary (code) hash slots */
    uint32_t codeLimit;       /* limit to main image signature range */
    uint8_t hashSize;       /* size of each hash in bytes */
    uint8_t hashType;       /* type of hash (cdHashType* constants) */
    uint8_t spare1;         /* unused (must be zero) */
    uint8_t pageSize;       /* log2(page size in bytes); 0 => infinite */
    uint32_t spare2;        /* unused (must be zero) */
    /* Version 0x20100 */
    uint32_t scatterOffset;       /* offset of optional scatter vector */
    /* followed by dynamic content as located by offset fields above */
} *code_directory_t;



void macho_parse(FILE *file, char *path, size_t size, symbol_table *symbols);
// file to be processed, path of the file, size of the file, and symbols to find in file

#endif

