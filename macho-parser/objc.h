#ifndef __objc_h
#define __objc_h

enum dyld_objc_2_class_type {
    dyld_objc_2_class_invalid_type = 0,
    dyld_objc_2_class_class_type,
    dyld_objc_2_class_metaclass_type
};

#define kObjc2SelRef     "__objc_selrefs"
#define kObjc2MsgRefs    "__objc_msgrefs"
#define kObjc2ClassRefs "__objc_classrefs"
#define kObjc2SuperRefs "__objc_superrefs"
#define kObjc2ClassList "__objc_classlist"
#define kObjc2NlClsList "__objc_nlclslist"
#define kObjc2CatList     "__objc_catlist"
#define kObjc2NlCatList "__objc_nlcatlist"
#define kObjc2ProtoList "__objc_protolist"
#define kObjc2ProtoRefs "__objc_protorefs"

struct dyld_objc_2_class_method_info {
    uint32_t entrySize;
    uint32_t count;
};

struct dyld_objc_2_class_protocol_info {
    uint64_t count;
};

struct dyld_objc_2_class_ivar_info {
    uint32_t entrySize;
    uint32_t count;
};

struct dyld_objc_2_class_property_info {
    uint32_t entrySize;
    uint32_t count;
};

struct dyld_objc_2_class_method {
    uint64_t name;
    uint64_t type;
    uint64_t imp;
};

struct dyld_objc_2_class_protocol {
    uint64_t isa;
    uint64_t name;
    uint64_t protocols;
    uint64_t instance_methods;
    uint64_t class_methods;
    uint64_t opt_instance_methods;
    uint64_t opt_class_methods;
    uint64_t instance_properties;
};

struct dyld_objc_2_class_ivar {
    uint64_t offset;
    uint64_t name;
    uint64_t type;
    uint32_t align;
    uint32_t size;
};

struct dyld_objc_2_class_property {
    char *name;
    char *attributes;
};

struct dyld_objc_2_class_data {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    uint64_t iVarLayout;
    uint64_t name; //char*
    uint64_t method; //struct dyld_objc_2_class_method_info*
    uint64_t protocol; //struct dyld_objc_2_class_protocol_info*
    uint64_t ivar; //struct dyld_objc_2_class_ivar_info*
    uint64_t weakIVarLayout;
    uint64_t property; //struct dyld_objc_2_class_property*
};

struct dyld_objc_2_class {
    struct dyld_objc_2_class *isa;
    uint64_t superCls;
    uint64_t cache;
    uint64_t vTable;
    struct dyld_objc_2_class_data *data;
};

#endif
