#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

int read_elf_header(int fd, Elf64_Ehdr *ehdr)
{
    if (lseek(fd, 0, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    if (read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr)) {
        printf("Error: reading ELF header\n");
        return -1;
    }

    return 0;
}

void print_elf_header(Elf64_Ehdr *ehdr)
{
    printf("ELF Header:\n");
    printf("  Magic:   %.4s\n", ehdr->e_ident);
    printf("  Class:                             %d\n", ehdr->e_ident[EI_CLASS]);
    printf("  Data:                              %d\n", ehdr->e_ident[EI_DATA]);
    printf("  Version:                           %d\n", ehdr->e_ident[EI_VERSION]);
    printf("  OS/ABI:                            %d\n", ehdr->e_ident[EI_OSABI]);
    printf("  ABI Version:                       %d\n", ehdr->e_ident[EI_ABIVERSION]);
    printf("  Type:                              %d\n", ehdr->e_type);
    printf("  Machine:                           %d\n", ehdr->e_machine);
    printf("  Version:                           %d\n", ehdr->e_version);
    printf("  Entry point address:               0x%lx\n", ehdr->e_entry);
    printf("  Start of program headers:          %ld (bytes into file)\n", ehdr->e_phoff);
    printf("  Start of section headers:          %ld (bytes into file)\n", ehdr->e_shoff);
    printf("  Flags:                             0x%x\n", ehdr->e_flags);
    printf("  Size of this header:               %d (bytes)\n", ehdr->e_ehsize);
    printf("  Size of program headers:           %d (bytes)\n", ehdr->e_phentsize);
    printf("  Number of program headers:         %d\n", ehdr->e_phnum);
    printf("  Size of section headers:           %d (bytes)\n", ehdr->e_shentsize);
    printf("  Number of section headers:         %d\n", ehdr->e_shnum);
    printf("  Section header string table index: %d\n", ehdr->e_shstrndx);
}

int read_program_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
    uint64_t phoff = ehdr->e_phoff;      // Start of program headers
    uint16_t phnum = ehdr->e_phnum;      // Number of program headers

    // Each program header has 56 byte
    for (uint16_t i = 0; i < phnum; i++) {
        if (lseek(fd, phoff + i * sizeof(Elf64_Phdr), SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (read(fd, &phdr[i], sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            printf("Error: reading program header\n");
            return -1;
        }
    }

    return 0;
}

void print_program_headers(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr)
{
    uint16_t phnum = ehdr->e_phnum;      // Number of program headers

    for (uint16_t i = 0; i < phnum; i++) {
        printf("Program Header %d:\n", i);
        printf("  Type:               0x%x\n", phdr[i].p_type);
        printf("  Flags:              0x%x\n", phdr[i].p_flags);
        printf("  Offset:             %ld\n", phdr[i].p_offset);
        printf("  Virtual Address:    0x%lx\n", phdr[i].p_vaddr);
        printf("  Physical Address:   0x%lx\n", phdr[i].p_paddr);
        printf("  File Size:          %ld\n", phdr[i].p_filesz);
        printf("  Memory Size:        %ld\n", phdr[i].p_memsz);
        printf("  Alignment:          %ld\n", phdr[i].p_align);
    }
}

int read_section_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr)
{
    uint64_t shoff = ehdr->e_shoff;          // Start of section headers
    uint16_t shnum = ehdr->e_shnum;          // Number of section headers
    uint16_t shentsize = ehdr->e_shentsize;  // Size of each section header

    // Each section header has 64 byte
    for (uint16_t i = 0; i < shnum; i++) {
        if (lseek(fd, shoff + i * shentsize, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (read(fd, &shdr[i], sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            printf("Error: reading section header\n");
            return -1;
        }
    }

    return 0;
}

void print_section_headers(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr)
{
    uint16_t shnum = ehdr->e_shnum;          // Number of section headers

    for (uint16_t i = 0; i < shnum; i++) {
        printf("Section Header %d:\n", i);
        printf("  Name:               %u\n", shdr[i].sh_name);
        printf("  Type:               0x%x\n", shdr[i].sh_type);
        printf("  Flags:              0x%lx\n", shdr[i].sh_flags);
        printf("  Address:            0x%lx\n", shdr[i].sh_addr);
        printf("  Offset:             %ld\n", shdr[i].sh_offset);
        printf("  Size:               %ld\n", shdr[i].sh_size);
        printf("  Link:               %u\n", shdr[i].sh_link);
        printf("  Info:               %u\n", shdr[i].sh_info);
        printf("  Address alignment:  %ld\n", shdr[i].sh_addralign);
        printf("  Entry size:         %ld\n", shdr[i].sh_entsize);
    }
}

int copy_sections(int fd, int new_fd, uint16_t shnum, Elf64_Shdr *shdr)
{
    for (uint16_t i = 0; i < shnum; i++) {
        if (shdr[i].sh_type == SHT_NOBITS) {
            continue;
        }

        if (lseek(fd, shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (lseek(new_fd, shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        char *buf = (char *)malloc(shdr[i].sh_size);
        if (read(fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: reading section\n");
            return -1;
        }

        if (write(new_fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        free(buf);
    }

    return 0;
}


int copy_elf_file(char *filename, char *new_filename)
{
    // --- Open files ---
    int fd = open(filename, O_RDONLY);
    int new_fd = open(new_filename, O_RDWR | O_CREAT, 0666);
    
    if (fd < 0 || new_fd < 0) {
        printf("Error: opening file\n");
        return -1;
    }

    // --- Copy ELF header ---
    Elf64_Ehdr ehdr;

    read_elf_header(fd, &ehdr);

    lseek(new_fd, 0, SEEK_SET);
    if (write(new_fd, &ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        printf("Error: writing ELF header\n");
        close(fd);
        close(new_fd);
        return -1;
    }

    // --- Copy program headers ---
    uint64_t phoff = ehdr.e_phoff;      // Start of program headers
    uint16_t phnum = ehdr.e_phnum;      // Number of program headers
    Elf64_Phdr phdr[phnum];             // Program header table (56 byte each entry)

    read_program_headers(fd, &ehdr, phdr);

    lseek(new_fd, phoff, SEEK_SET);
    for (uint16_t i = 0; i < phnum; i++) {
        if (write(new_fd, &phdr[i], sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            printf("Error: writing program header\n");
            close(fd);
            close(new_fd);
            return -1;
        }
    }

    // --- Copy sections ---
    uint64_t shoff = ehdr.e_shoff;          // Start of section headers
    uint16_t shnum = ehdr.e_shnum;          // Number of section headers
    Elf64_Shdr shdr[shnum];                 // Section header table (64 byte each entry)
    
    read_section_headers(fd, &ehdr, shdr);

    copy_sections(fd, new_fd, shnum, shdr);

    // --- Copy section headers ---
    lseek(new_fd, shoff, SEEK_SET);
    for (uint16_t i = 0; i < shnum; i++) {
        if (write(new_fd, &shdr[i], sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            printf("Error: writing section header\n");
            close(fd);
            close(new_fd);
            return -1;
        }
    }

    // --- Close files ---
    close(fd);
    close(new_fd);

    return 0;
}