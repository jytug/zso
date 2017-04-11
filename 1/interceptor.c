#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

#include "interceptor.h"

typedef Elf64_Ehdr      ehdr_t;
typedef Elf64_Phdr      phdr_t;
typedef Elf64_Sym       sym_t;
typedef Elf64_Dyn       dyn_t;
typedef Elf64_Rela      rela_t;
typedef Elf64_Addr      addr_t;
typedef Elf64_Xword     xword_t;



typedef struct {
    const char *fname;
    void *faddr;
} callback_communicator;

static int is_vdso(const phdr_t *phdr) {
    ehdr_t* ehdr_vdso = (ehdr_t *)getauxval(AT_SYSINFO_EHDR);
    phdr_t* phdr_vdso =
        (phdr_t *)(getauxval(AT_SYSINFO_EHDR) + ehdr_vdso->e_phoff);
    if (phdr_vdso == phdr)
        return 1;
    return 0;
}

static int resolve_callback(struct dl_phdr_info *info, size_t size, void *_data) {
    int j;

    /* omit the vDSO library */
    if (is_vdso(info->dlpi_phdr))
        return 0;

    callback_communicator *data = (callback_communicator *)_data;

    for (j = 0; j < info->dlpi_phnum; j++) {
        /* we only care about dynamic headers */
        if (info->dlpi_phdr[j].p_type != PT_DYNAMIC)
            continue;

        dyn_t *dyn_hdr =
            (dyn_t *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
        char *strtab;
        sym_t *symtab_base;

        /* search for the symbol table and the string table in this segment */
        for (; dyn_hdr->d_tag != DT_NULL; dyn_hdr++) {
            if (dyn_hdr->d_tag == DT_STRTAB)
                strtab = (char *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_SYMTAB)
                symtab_base = (sym_t *)(dyn_hdr->d_un.d_ptr);
        }

        /* use the fact that the string table is directly after the symbol table */
        for (sym_t *sym = symtab_base; (char *)sym != strtab; sym++) {
            if (sym->st_shndx == STN_UNDEF)
                continue;

            char *symbol_name = strtab + sym->st_name;
            if (strcmp(symbol_name, (char *)data->fname) == 0) {
                if ((sym->st_info % 16) == STT_FUNC) {
                    /* the first occurence of searched function is returned */
                    data->faddr = (void *)(info->dlpi_addr + sym->st_value);
                }
                if ((sym->st_info % 16) == STT_GNU_IFUNC) {
                    /* for an indirect function return its return value */
                    void *(*ifun)(void) =
                        (void *(*)())(info->dlpi_addr + sym->st_value);
                    data->faddr = ifun();
                }
                return 1;
            }
        }
    }
    return 0;
}

static void *resolve_function(const char *name) {
    callback_communicator rc;
    rc.fname = name;
    rc.faddr = NULL;
    dl_iterate_phdr(resolve_callback, &rc);
    return rc.faddr;
}

static int
substitute_callback(struct dl_phdr_info *info, size_t size, void *_data) {
    int j;

    /* omit the vDSO library */
    if (is_vdso(info->dlpi_phdr))
        return 0;

    callback_communicator *data = (callback_communicator *)_data;

    /* find .dynamic segment in an ELF file */
    for (j = 0; j < info->dlpi_phnum; j++) {
        if (info->dlpi_phdr[j].p_type != PT_DYNAMIC)
            continue;
        dyn_t *dyn_hdr =
            (dyn_t *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
        char *strtab;
        sym_t *symtab_base;
        rela_t *reloc_base;
        xword_t nreloc;

        /* search for the string table, symbol table and relocation table */
        for (; dyn_hdr->d_tag != DT_NULL; dyn_hdr++) {
            if (dyn_hdr->d_tag == DT_STRTAB)
                strtab = (char *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_SYMTAB)
                symtab_base = (sym_t *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_JMPREL)
                reloc_base = (rela_t *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_PLTRELSZ)
                nreloc = (xword_t)(dyn_hdr->d_un.d_val / sizeof(rela_t));
        }

        /* search for the apropriate R_X86_64_JUMP_SLOT relocation */
        for (rela_t *reloc = reloc_base; reloc != reloc_base + nreloc; reloc++) {
            if (ELF64_R_TYPE(reloc->r_info) != R_X86_64_JUMP_SLOT)
                continue;
            sym_t *sym = symtab_base + ELF64_R_SYM(reloc->r_info);
            char *symbol_name = strtab + sym->st_name;

            /* replace sought relocation with our own */
            addr_t *reloc_addr = (addr_t *)(info->dlpi_addr + reloc->r_offset);
            if (strcmp(symbol_name, data->fname) == 0) {
                *reloc_addr = (addr_t)(data->faddr);
                return 0;
            }
        }
    }
    return 0;
}

static void substitute(const char *name, void *new_func) {
    callback_communicator rc;
    rc.fname = name;
    rc.faddr = new_func;
    dl_iterate_phdr(substitute_callback, &rc);
}

void *intercept_function(const char *name, void *new_func) {
    void *old_func = resolve_function(name);
    substitute(name, new_func);
    return old_func;
}

void unintercept_function(const char *name) {
    void *old_func = resolve_function(name);
    substitute(name, old_func);
}
