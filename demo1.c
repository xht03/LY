#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

#include"function.h"

int main()
{
    int fd;
    char filename[50] = "/home/keats/LY/bin/hello";

    Elf64_Ehdr ehdr;    // ELF header (64 byte)

    fd = open(filename, O_RDWR);
    if (fd < 0) {
        printf("Error: opening file\n");
        return 1;
    }

    read_elf_header(fd, &ehdr);
    // print_elf_header(&ehdr);


    uint64_t phoff = ehdr.e_phoff;      // Start of program headers
    uint16_t phnum = ehdr.e_phnum;      // Number of program headers

    Elf64_Phdr phdr[phnum];             // Program header (56 byte)

    read_program_headers(fd, &ehdr, phdr);
    print_program_headers(&ehdr, phdr);
    
    uint64_t current_off = lseek(fd, 0, SEEK_CUR);

    printf("\ncurrent offset: %ld\n\n", current_off);


    // uint64_t shoff = ehdr.e_shoff;          // Start of section headers
    // uint16_t shnum = ehdr.e_shnum;          // Number of section headers
    // uint16_t shentsize = ehdr.e_shentsize;  // Size of each section header

    // for (uint16_t i = 0; i < shnum; i++) {
    //     Elf64_Shdr shdr;            // Section header (64 byte)

    //     if (lseek(fd, shoff + i * shentsize, SEEK_SET) < 0) {
    //         printf("Error: seeking section header\n");
    //         close(fd);
    //         return 1;
    //     }

    //     if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
    //         printf("Error: reading section header\n");
    //         close(fd);
    //         return 1;
    //     }

    //     printf("Section Header %d:\n", i);
    //     printf("  Name:               %u\n", shdr.sh_name);
    //     printf("  Type:               0x%x\n", shdr.sh_type);
    //     printf("  Flags:              0x%lx\n", shdr.sh_flags);
    //     printf("  Address:            0x%lx\n", shdr.sh_addr);
    //     printf("  Offset:             %ld\n", shdr.sh_offset);
    //     printf("  Size:               %ld\n", shdr.sh_size);
    //     printf("  Link:               %u\n", shdr.sh_link);
    //     printf("  Info:               %u\n", shdr.sh_info);
    //     printf("  Address alignment:  %ld\n", shdr.sh_addralign);
    //     printf("  Entry size:         %ld\n", shdr.sh_entsize);
    // }


    


    close(fd);
    return 0;
}