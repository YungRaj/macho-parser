#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

typedef int integer_t;
typedef integer_t    cpu_type_t;
typedef integer_t    cpu_subtype_t;
typedef int        vm_prot_t;


struct cpu_type_names {
    cpu_type_t cputype;
    const char* cpu_name;
};

#define NUM_CPUS 4
#define CPU_TYPE_I386    7
#define CPU_TYPE_X86_64 16777223
#define CPU_TYPE_ARM    12
#define CPU_TYPE_ARM64    16777228

static struct cpu_type_names cpu_type_names[] = {
    {CPU_TYPE_I386,        "i386"},
    {CPU_TYPE_X86_64,    "x86_64"},
    {CPU_TYPE_ARM,        "arm"},
    {CPU_TYPE_ARM64,    "arm64"}
};

#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca

/* Constant for the magic field of the mach_header (32-bit architectures) */
#define MH_MAGIC    0xfeedface    /* the mach magic number */
#define MH_CIGAM    0xcefaedfe    /* NXSwapInt(MH_MAGIC) */

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

/* Constants for the cmd field of all load commands, the type */
#define    LC_SEGMENT        0x1    /* segment of this file to be mapped */
#define    LC_SEGMENT_64    0x19    /* 64-bit segment of this file to be mapped */

struct fat_header {
    uint32_t    magic;        /* FAT_MAGIC */
    uint32_t    nfat_arch;    /* number of structs that follow */
};

struct fat_arch {
    cpu_type_t    cputype;    /* cpu specifier (int) */
    cpu_subtype_t    cpusubtype;    /* machine specifier (int) */
    uint32_t    offset;        /* file offset to this object file */
    uint32_t    size;        /* size of this object file */
    uint32_t    align;        /* alignment as a power of 2 */
};


/*
 * The 32-bit mach header appears at the very beginning of the object file for
 * 32-bit architectures.
 */
struct mach_header {
    uint32_t    magic;        /* mach magic number identifier */
    cpu_type_t    cputype;    /* cpu specifier */
    cpu_subtype_t    cpusubtype;    /* machine specifier */
    uint32_t    filetype;    /* type of file */
    uint32_t    ncmds;        /* number of load commands */
    uint32_t    sizeofcmds;    /* the size of all the load commands */
    uint32_t    flags;        /* flags */
};

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct mach_header_64 {
    uint32_t    magic;        /* mach magic number identifier */
    cpu_type_t    cputype;    /* cpu specifier */
    cpu_subtype_t    cpusubtype;    /* machine specifier */
    uint32_t    filetype;    /* type of file */
    uint32_t    ncmds;        /* number of load commands */
    uint32_t    sizeofcmds;    /* the size of all the load commands */
    uint32_t    flags;        /* flags */
    uint32_t    reserved;    /* reserved */
};

/*
 * The segment load command indicates that a part of this file is to be
 * mapped into the task's address space.  The size of this segment in memory,
 * vmsize, maybe equal to or larger than the amount to map from this file,
 * filesize.  The file is mapped starting at fileoff to the beginning of
 * the segment in memory, vmaddr.  The rest of the memory of the segment,
 * if any, is allocated zero fill on demand.  The segment's maximum virtual
 * memory protection and initial virtual memory protection are specified
 * by the maxprot and initprot fields.  If the segment has sections then the
 * section structures directly follow the segment command and their size is
 * reflected in cmdsize.
 */
struct segment_command { /* for 32-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT */
    uint32_t    cmdsize;    /* includes sizeof section structs */
    char        segname[16];    /* segment name */
    uint32_t    vmaddr;        /* memory address of this segment */
    uint32_t    vmsize;        /* memory size of this segment */
    uint32_t    fileoff;    /* file offset of this segment */
    uint32_t    filesize;    /* amount to map from the file */
    vm_prot_t    maxprot;    /* maximum VM protection */
    vm_prot_t    initprot;    /* initial VM protection */
    uint32_t    nsects;        /* number of sections in segment */
    uint32_t    flags;        /* flags */
};

/*
 * The 64-bit segment load command indicates that a part of this file is to be
 * mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
struct segment_command_64 { /* for 64-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT_64 */
    uint32_t    cmdsize;    /* includes sizeof section_64 structs */
    char        segname[16];    /* segment name */
    uint64_t    vmaddr;        /* memory address of this segment */
    uint64_t    vmsize;        /* memory size of this segment */
    uint64_t    fileoff;    /* file offset of this segment */
    uint64_t    filesize;    /* amount to map from the file */
    vm_prot_t    maxprot;    /* maximum VM protection */
    vm_prot_t    initprot;    /* initial VM protection */
    uint32_t    nsects;        /* number of sections in segment */
    uint32_t    flags;        /* flags */
};

/*
 * A segment is made up of zero or more sections.  Non-MH_OBJECT files have
 * all of their segments with the proper sections in each, and padded to the
 * specified segment alignment when produced by the link editor.  The first
 * segment of a MH_EXECUTE and MH_FVMLIB format file contains the mach_header
 * and load commands of the object file before its first section.  The zero
 * fill sections are always last in their segment (in all formats).  This
 * allows the zeroed segment padding to be mapped into memory where zero fill
 * sections might be. The gigabyte zero fill sections, those with the section
 * type S_GB_ZEROFILL, can only be in a segment with sections of this type.
 * These segments are then placed after all other segments.
 *
 * The MH_OBJECT format has all of its sections in one segment for
 * compactness.  There is no padding to a specified segment boundary and the
 * mach_header and load commands are not part of the segment.
 *
 * Sections with the same section name, sectname, going into the same segment,
 * segname, are combined by the link editor.  The resulting section is aligned
 * to the maximum alignment of the combined sections and is the new section's
 * alignment.  The combined sections are aligned to their original alignment in
 * the combined section.  Any padded bytes to get the specified alignment are
 * zeroed.
 *
 * The format of the relocation entries referenced by the reloff and nreloc
 * fields of the section structure for mach object files is described in the
 * header file <reloc.h>.
 */
struct section { /* for 32-bit architectures */
    char        sectname[16];    /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint32_t    addr;        /* memory address of this section */
    uint32_t    size;        /* size in bytes of this section */
    uint32_t    offset;        /* file offset of this section */
    uint32_t    align;        /* section alignment (power of 2) */
    uint32_t    reloff;        /* file offset of relocation entries */
    uint32_t    nreloc;        /* number of relocation entries */
    uint32_t    flags;        /* flags (section type and attributes)*/
    uint32_t    reserved1;    /* reserved (for offset or index) */
    uint32_t    reserved2;    /* reserved (for count or sizeof) */
};

struct section_64 { /* for 64-bit architectures */
    char        sectname[16];    /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint64_t    addr;        /* memory address of this section */
    uint64_t    size;        /* size in bytes of this section */
    uint32_t    offset;        /* file offset of this section */
    uint32_t    align;        /* section alignment (power of 2) */
    uint32_t    reloff;        /* file offset of relocation entries */
    uint32_t    nreloc;        /* number of relocation entries */
    uint32_t    flags;        /* flags (section type and attributes)*/
    uint32_t    reserved1;    /* reserved (for offset or index) */
    uint32_t    reserved2;    /* reserved (for count or sizeof) */
    uint32_t    reserved3;    /* reserved */
};




struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
#define LC_REQ_DYLD 0x80000000

/* Constants for the cmd field of all load commands, the type */
#define    LC_SEGMENT    0x1    /* segment of this file to be mapped */
#define    LC_SYMTAB    0x2    /* link-edit stab symbol table info */
#define    LC_SYMSEG    0x3    /* link-edit gdb symbol table info (obsolete) */
#define    LC_THREAD    0x4    /* thread */
#define    LC_UNIXTHREAD    0x5    /* unix thread (includes a stack) */
#define    LC_LOADFVMLIB    0x6    /* load a specified fixed VM shared library */
#define    LC_IDFVMLIB    0x7    /* fixed VM shared library identification */
#define    LC_IDENT    0x8    /* object identification info (obsolete) */
#define LC_FVMFILE    0x9    /* fixed VM file inclusion (internal use) */
#define LC_PREPAGE      0xa     /* prepage command (internal use) */
#define    LC_DYSYMTAB    0xb    /* dynamic link-edit symbol table info */
#define    LC_LOAD_DYLIB    0xc    /* load a dynamically linked shared library */
#define    LC_ID_DYLIB    0xd    /* dynamically linked shared lib ident */
#define LC_LOAD_DYLINKER 0xe    /* load a dynamic linker */
#define LC_ID_DYLINKER    0xf    /* dynamic linker identification */
#define    LC_PREBOUND_DYLIB 0x10    /* modules prebound for a dynamically */
/*  linked shared library */
#define    LC_ROUTINES    0x11    /* image routines */
#define    LC_SUB_FRAMEWORK 0x12    /* sub framework */
#define    LC_SUB_UMBRELLA 0x13    /* sub umbrella */
#define    LC_SUB_CLIENT    0x14    /* sub client */
#define    LC_SUB_LIBRARY  0x15    /* sub library */
#define    LC_TWOLEVEL_HINTS 0x16    /* two-level namespace lookup hints */
#define    LC_PREBIND_CKSUM  0x17    /* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
#define    LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)

#define    LC_SEGMENT_64    0x19    /* 64-bit segment of this file to be
mapped */
#define    LC_ROUTINES_64    0x1a    /* 64-bit image routines */
#define LC_UUID        0x1b    /* the uuid */
#define LC_RPATH       (0x1c | LC_REQ_DYLD)    /* runpath additions */
#define LC_CODE_SIGNATURE 0x1d    /* local of code signature */
#define LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
#define    LC_LAZY_LOAD_DYLIB 0x20    /* delay load of dylib until first use */
#define    LC_ENCRYPTION_INFO 0x21    /* encrypted segment information */
#define    LC_DYLD_INFO     0x22    /* compressed dyld information */
#define    LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)    /* compressed dyld information only */
#define    LC_LOAD_UPWARD_DYLIB (0x23 | LC_REQ_DYLD) /* load upward dylib */
#define LC_VERSION_MIN_MACOSX 0x24   /* build for MacOSX min OS version */
#define LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
#define LC_FUNCTION_STARTS 0x26 /* compressed table of function start addresses */
#define LC_DYLD_ENVIRONMENT 0x27 /* string for dyld to treat
like environment variable */
#define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
#define LC_DATA_IN_CODE 0x29 /* table of non-instructions in __text */
#define LC_SOURCE_VERSION 0x2A /* source version used to build binary */
#define LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */

/*
 * A variable length string in a load command is represented by an lc_str
 * union.  The strings are stored just after the load command structure and
 * the offset is from the start of the load command structure.  The size
 * of the string is reflected in the cmdsize field of the load command.
 * Once again any padded bytes to bring the cmdsize field to a multiple
 * of 4 bytes must be zero.
 */
union lc_str {
    uint32_t    offset;    /* offset to the string */
#ifndef __LP64__
    char        *ptr;    /* pointer to the string */
#endif
};

/*
 * Dynamically linked shared libraries are identified by two things.  The
 * pathname (the name of the library as found for execution), and the
 * compatibility version number.  The pathname must match and the compatibility
 * number in the user of the library must be greater than or equal to the
 * library being used.  The time stamp is used to record the time a library was
 * built and copied into user so it can be use to determined if the library used
 * at runtime is exactly the same as used to built the program.
 */
struct dylib {
    union lc_str  name;            /* library's path name */
    uint32_t timestamp;            /* library's build time stamp */
    uint32_t current_version;        /* library's current version number */
    uint32_t compatibility_version;    /* library's compatibility vers number*/
};

/*
 * A dynamically linked shared library (filetype == MH_DYLIB in the mach header)
 * contains a dylib_command (cmd == LC_ID_DYLIB) to identify the library.
 * An object that uses a dynamically linked shared library also contains a
 * dylib_command (cmd == LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, or
 * LC_REEXPORT_DYLIB) for each library it uses.
 */
struct dylib_command {
    uint32_t    cmd;        /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
                             LC_REEXPORT_DYLIB */
    uint32_t    cmdsize;    /* includes pathname string */
    struct dylib    dylib;        /* the library identification */
};

/*
 * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
 * "stab" style symbol table information as described in the header files
 * <nlist.h> and <stab.h>.
 */

struct symtab_command {
    uint32_t    cmd;        /* LC_SYMTAB */
    uint32_t    cmdsize;    /* sizeof(struct symtab_command) */
    uint32_t    symoff;        /* symbol table offset */
    uint32_t    nsyms;        /* number of symbol table entries */
    uint32_t    stroff;        /* string table offset */
    uint32_t    strsize;    /* string table size in bytes */
};

/*
 * This is the second set of the symbolic information which is used to support
 * the data structures for the dynamically link editor.
 *
 * The original set of symbolic information in the symtab_command which contains
 * the symbol and string tables must also be present when this load command is
 * present.  When this load command is present the symbol table is organized
 * into three groups of symbols:
 *    local symbols (static and debugging symbols) - grouped by module
 *    defined external symbols - grouped by module (sorted by name if not lib)
 *    undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
 *                         and in order the were seen by the static
 *                    linker if MH_BINDATLOAD is set)
 * In this load command there are offsets and counts to each of the three groups
 * of symbols.
 *
 * This load command contains a the offsets and sizes of the following new
 * symbolic information tables:
 *    table of contents
 *    module table
 *    reference symbol table
 *    indirect symbol table
 * The first three tables above (the table of contents, module table and
 * reference symbol table) are only present if the file is a dynamically linked
 * shared library.  For executable and object modules, which are files
 * containing only one module, the information that would be in these three
 * tables is determined as follows:
 *     table of contents - the defined external symbols are sorted by name
 *    module table - the file contains only one module so everything in the
 *               file is part of the module.
 *    reference symbol table - is the defined and undefined external symbols
 *
 * For dynamically linked shared library files this load command also contains
 * offsets and sizes to the pool of relocation entries for all sections
 * separated into two groups:
 *    external relocation entries
 *    local relocation entries
 * For executable and object modules the relocation entries continue to hang
 * off the section structures.
 */
struct dysymtab_command {
    uint32_t cmd;    /* LC_DYSYMTAB */
    uint32_t cmdsize;    /* sizeof(struct dysymtab_command) */
    
    /*
     * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
     * are grouped into the following three groups:
     *    local symbols (further grouped by the module they are from)
     *    defined external symbols (further grouped by the module they are from)
     *    undefined symbols
     *
     * The local symbols are used only for debugging.  The dynamic binding
     * process may have to use them to indicate to the debugger the local
     * symbols for a module that is being bound.
     *
     * The last two groups are used by the dynamic binding process to do the
     * binding (indirectly through the module table and the reference symbol
     * table when this is a dynamically linked shared library file).
     */
    uint32_t ilocalsym;    /* index to local symbols */
    uint32_t nlocalsym;    /* number of local symbols */
    
    uint32_t iextdefsym;/* index to externally defined symbols */
    uint32_t nextdefsym;/* number of externally defined symbols */
    
    uint32_t iundefsym;    /* index to undefined symbols */
    uint32_t nundefsym;    /* number of undefined symbols */
    
    /*
     * For the for the dynamic binding process to find which module a symbol
     * is defined in the table of contents is used (analogous to the ranlib
     * structure in an archive) which maps defined external symbols to modules
     * they are defined in.  This exists only in a dynamically linked shared
     * library file.  For executable and object modules the defined external
     * symbols are sorted by name and is use as the table of contents.
     */
    uint32_t tocoff;    /* file offset to table of contents */
    uint32_t ntoc;    /* number of entries in table of contents */
    
    /*
     * To support dynamic binding of "modules" (whole object files) the symbol
     * table must reflect the modules that the file was created from.  This is
     * done by having a module table that has indexes and counts into the merged
     * tables for each module.  The module structure that these two entries
     * refer to is described below.  This exists only in a dynamically linked
     * shared library file.  For executable and object modules the file only
     * contains one module so everything in the file belongs to the module.
     */
    uint32_t modtaboff;    /* file offset to module table */
    uint32_t nmodtab;    /* number of module table entries */
    
    /*
     * To support dynamic module binding the module structure for each module
     * indicates the external references (defined and undefined) each module
     * makes.  For each module there is an offset and a count into the
     * reference symbol table for the symbols that the module references.
     * This exists only in a dynamically linked shared library file.  For
     * executable and object modules the defined external symbols and the
     * undefined external symbols indicates the external references.
     */
    uint32_t extrefsymoff;    /* offset to referenced symbol table */
    uint32_t nextrefsyms;    /* number of referenced symbol table entries */
    
    /*
     * The sections that contain "symbol pointers" and "routine stubs" have
     * indexes and (implied counts based on the size of the section and fixed
     * size of the entry) into the "indirect symbol" table for each pointer
     * and stub.  For every section of these two types the index into the
     * indirect symbol table is stored in the section header in the field
     * reserved1.  An indirect symbol table entry is simply a 32bit index into
     * the symbol table to the symbol that the pointer or stub is referring to.
     * The indirect symbol table is ordered to match the entries in the section.
     */
    uint32_t indirectsymoff; /* file offset to the indirect symbol table */
    uint32_t nindirectsyms;  /* number of indirect symbol table entries */
    
    /*
     * To support relocating an individual module in a library file quickly the
     * external relocation entries for each module in the library need to be
     * accessed efficiently.  Since the relocation entries can't be accessed
     * through the section headers for a library file they are separated into
     * groups of local and external entries further grouped by module.  In this
     * case the presents of this load command who's extreloff, nextrel,
     * locreloff and nlocrel fields are non-zero indicates that the relocation
     * entries of non-merged sections are not referenced through the section
     * structures (and the reloff and nreloc fields in the section headers are
     * set to zero).
     *
     * Since the relocation entries are not accessed through the section headers
     * this requires the r_address field to be something other than a section
     * offset to identify the item to be relocated.  In this case r_address is
     * set to the offset from the vmaddr of the first LC_SEGMENT command.
     * For MH_SPLIT_SEGS images r_address is set to the the offset from the
     * vmaddr of the first read-write LC_SEGMENT command.
     *
     * The relocation entries are grouped by module and the module table
     * entries have indexes and counts into them for the group of external
     * relocation entries for that the module.
     *
     * For sections that are merged across modules there must not be any
     * remaining external relocation entries for them (for merged sections
     * remaining relocation entries must be local).
     */
    uint32_t extreloff;    /* offset to external relocation entries */
    uint32_t nextrel;    /* number of external relocation entries */
    
    /*
     * All the local relocation entries are grouped together (they are not
     * grouped by their module since they are only used if the object is moved
     * from it staticly link edited address).
     */
    uint32_t locreloff;    /* offset to local relocation entries */
    uint32_t nlocrel;    /* number of local relocation entries */
    
};



void macho_parse(FILE *file,size_t size);
