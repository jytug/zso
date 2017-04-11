#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

#include "interceptor.h"

typedef struct {
    const char *fname;
    void *faddr;
} callback_communicator;

static int resolve_callback(struct dl_phdr_info *info, size_t size, void *_data) {
    int j;

    /* omit the vDSO library */
    Elf64_Ehdr* ehdr_vdso = (Elf64_Ehdr *)getauxval(AT_SYSINFO_EHDR);
    Elf64_Phdr* phdr_vdso =
        (Elf64_Phdr *)(getauxval(AT_SYSINFO_EHDR) + ehdr_vdso->e_phoff);
    if (phdr_vdso == info->dlpi_phdr)
        return 0;

    callback_communicator *data = (callback_communicator *)_data;

    for (j = 0; j < info->dlpi_phnum; j++) {
        if (info->dlpi_phdr[j].p_type != PT_DYNAMIC)
            continue;

        Elf64_Dyn *dyn_hdr =
            (Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
        char *strtab;
        Elf64_Sym *symtab;

        /* search for the symbol table and the string table in this segment */
        for (; dyn_hdr->d_tag != DT_NULL; dyn_hdr++) {
            if (dyn_hdr->d_tag == DT_STRTAB)
                strtab = (char *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_SYMTAB)
                symtab = (Elf64_Sym *)(dyn_hdr->d_un.d_ptr);
        }

        /* use the fact that the string table is directly after the symbol table */
        for (Elf64_Sym *ii = symtab; (char *)ii != strtab; ii++) {
            if (ii->st_shndx == STN_UNDEF)
                continue;
            //printf("%d, STT_FUNC = %d\n", ii->st_info % 16);

            char *symbol_name = strtab + ii->st_name;
            if (strcmp(symbol_name, (char *)data->fname) == 0 &&
                    (ii->st_info % 16) == STT_FUNC) {
                /* the first occurence of searched function is returned */
                data->faddr = (void *)(info->dlpi_addr + ii->st_value);
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
    Elf64_Ehdr* ehdr_vdso = (Elf64_Ehdr *)getauxval(AT_SYSINFO_EHDR);
    Elf64_Phdr* phdr_vdso =
        (Elf64_Phdr *)(getauxval(AT_SYSINFO_EHDR) + ehdr_vdso->e_phoff);
    if (phdr_vdso == info->dlpi_phdr)
        return 0;

    callback_communicator *data = (callback_communicator *)_data;

    /* find .dynamic segment in an ELF file */
    for (j = 0; j < info->dlpi_phnum; j++) {
        if (info->dlpi_phdr[j].p_type != PT_DYNAMIC)
            continue;
        Elf64_Dyn *dyn_hdr =
            (Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
        char *strtab;
        Elf64_Sym *symtab;
        Elf64_Rela *reloc;
        Elf64_Xword nreloc;

        /* search for the string table, symbol table and relocation table */
        for (; dyn_hdr->d_tag != DT_NULL; dyn_hdr++) {
            if (dyn_hdr->d_tag == DT_STRTAB)
                strtab = (char *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_SYMTAB)
                symtab = (Elf64_Sym *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_JMPREL)
                reloc = (Elf64_Rela *)(dyn_hdr->d_un.d_ptr);
            if (dyn_hdr->d_tag == DT_PLTRELSZ)
                nreloc = (Elf64_Xword)(dyn_hdr->d_un.d_val / sizeof(Elf64_Rela));
        }

        for (Elf64_Rela *ii = reloc; ii != reloc + nreloc; ii++) {
            if (ELF64_R_TYPE(ii->r_info) != R_X86_64_JUMP_SLOT)
                continue;
            Elf64_Sym *sym = symtab + ELF64_R_SYM(ii->r_info);
            char *symbol_name = strtab + sym->st_name;

            /* replace sought relocation with our own */
            Elf64_Addr *reloc_addr = (Elf64_Addr *)(info->dlpi_addr + ii->r_offset);
            if (strcmp(symbol_name, data->fname) == 0) {
                *reloc_addr = (Elf64_Addr)(data->faddr);
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
