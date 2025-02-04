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
    print_elf_header(&ehdr);


    uint64_t phoff = ehdr.e_phoff;      // Start of program headers
    uint16_t phnum = ehdr.e_phnum;      // Number of program headers

    Elf64_Phdr phdr[phnum];             // Program header (56 byte)

    read_program_headers(fd, &ehdr, phdr);
    print_program_headers(&ehdr, phdr);

    uint64_t shoff = ehdr.e_shoff;          // Start of section headers
    uint16_t shnum = ehdr.e_shnum;          // Number of section headers

    Elf64_Shdr shdr[shnum];                 // Section header (64 byte)

    read_section_headers(fd, &ehdr, shdr);
    print_section_headers(&ehdr, shdr);

    close(fd);
    return 0;
}