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




void macho_parse(FILE *file,size_t size);
void* macho_load_bytes(uint32_t offset, uint32_t size);

#endif

