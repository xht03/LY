#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

#include "function.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define CONGRUENT(x, a) ((x) % (a))

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

char* read_string_table(int fd, Elf64_Ehdr *ehdr)
{
    uint16_t shstrndx = ehdr->e_shstrndx;       // Section header string table index
    uint16_t shnum = ehdr->e_shnum;             // Number of section headers
    Elf64_Shdr shdr[shnum];                     // Section header table (64 byte each entry)

    if (shstrndx >= shnum) {
        printf("Error: section header string table index is invalid\n");
        return -1;
    }

    // --- Read section headers ---
    if (lseek(fd, ehdr->e_shoff, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    if (read(fd, shdr, shnum * sizeof(Elf64_Shdr)) != shnum * sizeof(Elf64_Shdr)) {
        printf("Error: reading section headers\n");
        return -1;
    }

    // --- Read section header string table ---
    if (lseek(fd, shdr[shstrndx].sh_offset, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    char *shstrtab = (char *)malloc(shdr[shstrndx].sh_size);

    if (read(fd, shstrtab, shdr[shstrndx].sh_size) != shdr[shstrndx].sh_size) {
        printf("Error: reading section header string table\n");
        return -1;
    }

    // --- Print section header string table ---
    for(int i = 0; i < shnum; i++) {
        printf("Section %d: %s\n", i, shstrtab + shdr[i].sh_name);
    }

    return shstrtab;
}

char* read_section_by_index(int fd, uint16_t index)
{
    Elf64_Ehdr ehdr;
    read_elf_header(fd, &ehdr);

    Elf64_Shdr shdr[ehdr.e_shnum];
    read_section_headers(fd, &ehdr, &shdr);

    char *buf = (char *)malloc(shdr[index].sh_size);

    if (lseek(fd, shdr[index].sh_offset, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return NULL;
    }

    if (read(fd, buf, shdr[index].sh_size) != shdr[index].sh_size) {
        printf("Error: reading section\n");
        return NULL;
    }

    return buf;
}

uint16_t get_section_index_by_name(int fd, char *section_name)
{
    Elf64_Ehdr ehdr;
    read_elf_header(fd, &ehdr);

    Elf64_Shdr shdr[ehdr.e_shnum];
    read_section_headers(fd, &ehdr, &shdr);

    char *shstrtab = read_string_table(fd, &ehdr);

    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        if (strcmp(shstrtab + shdr[i].sh_name, section_name) == 0) {
            return i;
        }
    }

    free(shstrtab);

    return -1;
}

SecList* get_seg2sec_mapping(int fd)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr phdr[ehdr.e_phnum];
    Elf64_Shdr shdr[ehdr.e_shnum];

    read_elf_header(fd, &ehdr);
    read_program_headers(fd, &ehdr, phdr);
    read_section_headers(fd, &ehdr, shdr);

    SecList *seg2sec = (SecList *)malloc(ehdr.e_phnum * sizeof(SecList));

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        seg2sec[i].sec_num = 0;
        seg2sec[i].sec_idx = (uint16_t *)malloc(ehdr.e_shnum * sizeof(uint16_t));
    }

    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        for (uint16_t j = 0; j < ehdr.e_phnum; j++) {
            if (shdr[i].sh_offset >= phdr[j].p_offset && shdr[i].sh_offset < phdr[j].p_offset + phdr[j].p_filesz) {
                seg2sec[j].sec_idx[seg2sec[j].sec_num] = i;
                seg2sec[j].sec_num++;
            }
        }
    }

    // print the mapping relationship
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        printf("Segment %d: ", i);
        for (uint16_t j = 0; j < seg2sec[i].sec_num; j++) {
            printf("%d ", seg2sec[i].sec_idx[j]);
        }
        printf("\n");
    }

    return seg2sec;
}

int free_seg2sec_mapping(SecList *seg2sec, Elf64_Ehdr *ehdr)
{
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        free(seg2sec[i].sec_idx);
    }

    free(seg2sec);

    return 0;
}

int copy_elf_header(int new_fd, Elf64_Ehdr *ehdr)
{
    if (lseek(new_fd, 0, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    if (write(new_fd, ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        printf("Error: writing ELF header\n");
        return -1;
    }

    return 0;
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

int compare_phdr(const void *a, const void *b) {
    Elf64_Phdr *phdr_a = (Elf64_Phdr *)a;
    Elf64_Phdr *phdr_b = (Elf64_Phdr *)b;

    if (phdr_a->p_vaddr < phdr_b->p_vaddr) {
        return -1;
    } else if (phdr_a->p_vaddr > phdr_b->p_vaddr) {
        return 1;
    } else {
        return 0;
    }
}

void sort_phdr_by_vaddr(Elf64_Phdr phdr[], size_t phnum) {
    qsort(phdr, phnum, sizeof(Elf64_Phdr), compare_phdr);
}

uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size)
{
    /**
     * @brief Create a trampoline section at the end of the elf file. Return the virtual address of the trampoline section.
     * 
     * @note The trampoline section must be loadable into memory and executable.
     */

    uint64_t off = 0;       // To locate offset in the new file
    uint64_t addr = 0;      // To locate virtual address in the new file

    // --- Collect information ---
    Elf64_Ehdr ehdr;
    read_elf_header(fd, &ehdr);

    Elf64_Phdr phdr[ehdr.e_phnum];
    read_program_headers(fd, &ehdr, phdr);

    Elf64_Shdr shdr[ehdr.e_shnum];
    read_section_headers(fd, &ehdr, shdr);

    SecList *seg2sec = get_seg2sec_mapping(fd);

    // --- Create new elf header ---
    /**
     * @brief 
     * 1. adjust entry point (do it later)
     * 2. adjust start of section headers (do it later)
     * 3. number of section headers + 1
     * 4. section header string table index + 1
     */

    Elf64_Ehdr new_ehdr = ehdr;
    new_ehdr.e_shnum += 1;
    new_ehdr.e_shstrndx += 1;

    // --- Create new section headers ---
    /**
     * @brief 
     * 1. Copy all section headers before .text
     * 2. Create a new section header for the trampoline section
     * 3. Copy all section headers after .text
     * 4. Extend the section header string table
     * 5. Adjust the offset of each section header
     * 6. Adjust the address of each section header (do it later)
     */

    Elf64_Shdr new_shdr[new_ehdr.e_shnum];

    uint16_t textIdx = get_section_index_by_name(fd, ".text");
    uint16_t bssIdx = get_section_index_by_name(fd, ".bss");

    for (uint16_t i = 0; i <= textIdx; i++) {
        new_shdr[i] = shdr[i];
    }

    off = new_shdr[textIdx].sh_offset + new_shdr[textIdx].sh_size;

    new_shdr[textIdx + 1].sh_name = shdr[ehdr.e_shstrndx].sh_size;
    new_shdr[textIdx + 1].sh_type = SHT_PROGBITS;
    new_shdr[textIdx + 1].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_shdr[textIdx + 1].sh_addr = 0;  // To be filled later
    new_shdr[textIdx + 1].sh_offset = ALIGN_UP(off, 16);
    new_shdr[textIdx + 1].sh_size = section_size;
    new_shdr[textIdx + 1].sh_link = 0;
    new_shdr[textIdx + 1].sh_info = 0;
    new_shdr[textIdx + 1].sh_addralign = 16;
    new_shdr[textIdx + 1].sh_entsize = 0;

    off = new_shdr[textIdx + 1].sh_offset + new_shdr[textIdx + 1].sh_size;

    for (uint16_t i = textIdx + 2; i < new_ehdr.e_shnum; i++) {
        new_shdr[i] = shdr[i - 1];
        new_shdr[i].sh_offset = ALIGN_UP(off, shdr[i - 1].sh_addralign);

        // need to add the new section name to shstrtab
        if (i == new_ehdr.e_shstrndx) {
            new_shdr[i].sh_size += strlen(section_name) + 1;
        }

        off = new_shdr[i].sh_offset + new_shdr[i].sh_size;
    }

    

    new_ehdr.e_shoff = ALIGN_UP(off, 8);

    // --- Create new program headers ---
    /**
     * @brief Allocate memory space to 4 loadable segments first, which contain the remaining segments.
     */
    Elf64_Phdr new_phdr[ehdr.e_phnum];

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {

            uint16_t startIdx = seg2sec[i].sec_idx[0];
            if (startIdx > textIdx) {
                startIdx += 1;
            }

            uint16_t endIdx = seg2sec[i].sec_idx[seg2sec[i].sec_num - 1];
            if (endIdx > textIdx) {
                endIdx += 1;
            }

            new_phdr[i].p_type = PT_LOAD;
            new_phdr[i].p_flags = phdr[i].p_flags;
            new_phdr[i].p_offset = shdr[startIdx].sh_offset;
            new_phdr[i].p_align = phdr[i].p_align;
            new_phdr[i].p_vaddr = ALIGN_UP(addr, new_phdr[i].p_align) + CONGRUENT(new_shdr[startIdx].sh_offset, new_phdr[i].p_align);
            new_phdr[i].p_paddr = new_phdr[i].p_vaddr;
            new_phdr[i].p_filesz = shdr[endIdx].sh_offset + shdr[endIdx].sh_size - shdr[startIdx].sh_offset;
            new_phdr[i].p_memsz = new_phdr[i].p_filesz;

            if (bssIdx + 1 >= startIdx && bssIdx + 1 <= endIdx) {
                new_phdr[i].p_memsz += 8;
            }
            
            for (uint16_t j = startIdx; j <= endIdx; j++) {
                new_shdr[j].sh_addr = new_phdr[i].p_vaddr + (new_shdr[j].sh_offset - shdr[startIdx].sh_offset);
            }

            addr = new_phdr[i].p_vaddr + new_phdr[i].p_memsz;
        }
    }

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {

            uint16_t startIdx = seg2sec[i].sec_idx[0];
            if (startIdx > textIdx) {
                startIdx += 1;
            }

            uint16_t endIdx = seg2sec[i].sec_idx[seg2sec[i].sec_num - 1];
            if (endIdx > textIdx) {
                endIdx += 1;
            }

            new_phdr[i].p_type = phdr[i].p_type;
            new_phdr[i].p_flags = phdr[i].p_flags;
            new_phdr[i].p_offset = shdr[startIdx].sh_offset;
            new_phdr[i].p_vaddr = shdr[startIdx].sh_addr;
            new_phdr[i].p_paddr = shdr[startIdx].sh_addr;
            new_phdr[i].p_filesz = shdr[endIdx].sh_offset + shdr[endIdx].sh_size - shdr[startIdx].sh_offset;
            new_phdr[i].p_memsz = new_phdr[i].p_filesz;
            new_phdr[i].p_align = phdr[i].p_align;
        }
    }

    new_ehdr.e_entry = new_shdr[textIdx].sh_addr;

    // --- Write new elf header ---
    if (lseek(new_fd, 0, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    if (write(new_fd, &new_ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        printf("Error: writing ELF header\n");
        return -1;
    }
    
    // --- Write program headers ---

    if (lseek(new_fd, new_ehdr.e_phoff, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    for (uint16_t i = 0; i < new_ehdr.e_phnum; i++) {
        if (lseek(new_fd, new_ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (write(new_fd, &new_phdr[i], sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            printf("Error: writing program header\n");
            return -1;
        }
    }

    // --- Write sections ---

    for (uint16_t i = 0; i <= textIdx; i++) {
        char *buf = (char *)malloc(shdr[i].sh_size);

        if (lseek(fd, shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if(lseek(new_fd, new_shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (read(fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        
        if(write(new_fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        free(buf);
    }

    for (uint16_t i = textIdx + 1; i < ehdr.e_shnum; i++) {
        char *buf = (char *)malloc(shdr[i].sh_size);

        if (lseek(fd, shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if(lseek(new_fd, new_shdr[i + 1].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (read(fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }
        
        if(write(new_fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        free(buf);

        // Write the new section name into shstrtab
        if (i == ehdr.e_shstrndx) {
            if (lseek(new_fd, new_shdr[i + 1].sh_offset + shdr[i].sh_size, SEEK_SET) < 0) {
                printf("Error: lseek\n");
                return -1;
            }

            if (write(new_fd, section_name, strlen(section_name) + 1) != strlen(section_name) + 1) {
                printf("Error: writing section\n");
                return -1;
            }
        }
    }

    // --- Write new section headers ---

    if (lseek(new_fd, new_ehdr.e_shoff, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    for (uint16_t i = 0; i < new_ehdr.e_shnum; i++) {
        if (lseek(new_fd, new_ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (write(new_fd, &new_shdr[i], sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
            printf("Error: writing section header\n");
            return -1;
        }
    }

    // --- Close files ---

    free_seg2sec_mapping(seg2sec, &ehdr);
    close(fd);
    close(new_fd);
    
    return new_shdr[textIdx + 1].sh_addr;
}