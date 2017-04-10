#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>

#include "interceptor.h"

int dummy = 0;

static int callback(struct dl_phdr_info *info, size_t size, void *data) {
    dummy++;
    if (dummy == 2)
        return 0;
    int j;
    printf("name=%s (%d segments)\n", info->dlpi_name,
            info->dlpi_phnum);

    for (j = 0; j < info->dlpi_phnum; j++) {
        if (info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
            printf("\t\theader %2d: address=%10p\n", j,
                    (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
            Elf64_Dyn *dyn_hdr =
                (Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
            char *strtab;
            Elf64_Sym *symtab;
            Elf64_Word *hash;
            for (; dyn_hdr->d_tag != DT_NULL; dyn_hdr++) {
                if (dyn_hdr->d_tag == DT_STRTAB)
                    strtab = (char *)(dyn_hdr->d_un.d_ptr);
                if (dyn_hdr->d_tag == DT_SYMTAB)
                    symtab = (Elf64_Sym *)(dyn_hdr->d_un.d_ptr);
                if (dyn_hdr->d_tag == DT_HASH)
                    hash = (Elf64_Word *)(dyn_hdr->d_un.d_ptr);
            }
            printf("\t\tsymbol table: \t%10p\n\t\tstring table: \t%10p\n\t\thash: \t\t%10p\n",
                    symtab, strtab, hash);
            if (hash) {
                Elf64_Word nbucket = hash[0];
                Elf64_Word nchain = hash[1];
                Elf64_Word *bucket = hash + 2;
                Elf64_Word *chain = hash + 2 + nbucket;
                printf("nchain = %d\n", nchain);
                for (int i = 0; i < nchain; i++) {
                    Elf64_Sym *ii = symtab + i;
                    printf("symbol: %s, address: %p\n",
                           strtab + ii->st_name,
                           (void *)(info->dlpi_addr + ii->st_value));
                }
            }
        }
    }
    return 0;
}

void *intercept_function(const char *name, void *new_func) {
    dl_iterate_phdr(callback, NULL);
    printf("puts address: %p", (void *)puts);
    return new_func;
}

void unintercept_function(const char *name) {

}
