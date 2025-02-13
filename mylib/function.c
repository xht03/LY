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

int read_string_table(int fd, Elf64_Ehdr *ehdr, char *shstrtab)
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

    shstrtab = (char *)malloc(shdr[shstrndx].sh_size);

    if (read(fd, shstrtab, shdr[shstrndx].sh_size) != shdr[shstrndx].sh_size) {
        printf("Error: reading section header string table\n");
        return -1;
    }

    // --- Print section header string table ---
    // for(int i = 0; i < shnum; i++) {
    //     printf("Section %d: %s\n", i, shstrtab + shdr[i].sh_name);
    // }

    return 0;
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
    Elf64_Shdr shdr[ehdr.e_shnum];
    char *shstrtab;

    read_elf_header(fd, &ehdr);
    read_section_headers(fd, &ehdr, &shdr);
    read_string_table(fd, &ehdr, shstrtab);

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

uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size, uint64_t section_align)
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

    // --- Make elf header ---
    /**
    * 1. the number of program headers + 1
    * 2. the number of section headers + 1
    ** 3. start of section headers would change later
    ** 4. Entry point address may change later
    *
    */

    Elf64_Ehdr new_ehdr;
    
    memcpy(&new_ehdr, &ehdr, sizeof(Elf64_Ehdr));

    new_ehdr.e_phnum += 1;
    new_ehdr.e_shnum += 1;

    // --- Copy section headers ---

    Elf64_Shdr new_shdr[new_ehdr.e_shnum];
    memcpy(new_shdr, shdr, ehdr.e_shnum * sizeof(Elf64_Shdr));

    // --- Copy sections and adjust offset, address ---

    off = sizeof(Elf64_Ehdr) + new_ehdr.e_phnum * sizeof(Elf64_Phdr);
    addr = sizeof(Elf64_Ehdr) + new_ehdr.e_phnum * sizeof(Elf64_Phdr);

    /* shdr[0] is a null section */

    for (uint16_t i = 1; i < ehdr.e_shnum; i++) {

        if (shdr[i].sh_size == 0) {
            continue;
        }

        // Calculate alignment
        uint64_t shr_align = MAX(shdr[i].sh_addralign, 1);          // Section alignment
        uint64_t phr_align = 1;                                     // Program header alignment

        for (uint16_t j = 0; j < ehdr.e_phnum; j++) {
            if (seg2sec[j].sec_num == 0) {
                continue;
            }

            if (seg2sec[j].sec_idx[0] == i) {
                phr_align = MAX(phr_align, phdr[j].p_align);
            }
        }

        uint64_t align = MAX(shr_align, phr_align);     // Final alignment

        // Calculate start offset
        new_shdr[i].sh_offset = ALIGN_UP(off, align);

        // Write into new file
        char *buf = read_section_by_index(fd, i);       // Section data
        
        if (lseek(new_fd, new_shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }
        if (write(new_fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        // Update new offset
        off = new_shdr[i].sh_offset + shdr[i].sh_size;

        // Calculate start address (if the section is loadable)
        if (shdr[i].sh_flags & SHF_ALLOC) {
            new_shdr[i].sh_addr = ALIGN_UP(addr, align);
            addr = new_shdr[i].sh_addr + shdr[i].sh_size;
        }
        else {
            new_shdr[i].sh_addr = 0;
        }

        // If the section is the section header string table
        // Add the trampline section name to the end of the string table
        if (i == ehdr.e_shstrndx) {
            
            if(lseek(new_fd, off, SEEK_SET) < 0) {
                printf("Error: lseek\n");
                return -1;
            }

            if(write(new_fd, section_name, strlen(section_name) + 1) != strlen(section_name) + 1) {
                printf("Error: writing section name\n");
                return -1;
            }

            new_shdr[i].sh_size += strlen(section_name) + 1;
            
            off += strlen(section_name) + 1;
            // addr += strlen(section_name) + 1;
        }
    }

    // --- Create trampoline section ---

    uint64_t trampoline_off = ALIGN_UP(off, section_align);
    uint64_t trampoline_addr = ALIGN_UP(addr, section_align);

    /* Update its section header */
    new_shdr[ehdr.e_shnum].sh_name = shdr[ehdr.e_shstrndx].sh_size;
    new_shdr[ehdr.e_shnum].sh_type = SHT_PROGBITS;
    new_shdr[ehdr.e_shnum].sh_flags = SHF_ALLOC | SHF_EXECINSTR;        // same to BiRFIA
    new_shdr[ehdr.e_shnum].sh_addr = trampoline_addr;
    new_shdr[ehdr.e_shnum].sh_offset = trampoline_off;
    new_shdr[ehdr.e_shnum].sh_size = section_size;
    new_shdr[ehdr.e_shnum].sh_link = 0;
    new_shdr[ehdr.e_shnum].sh_info = 0;
    new_shdr[ehdr.e_shnum].sh_addralign = section_align;
    new_shdr[ehdr.e_shnum].sh_entsize = 0;

    off = trampoline_off + section_size;
    addr = trampoline_addr + section_size;


    // --- Update and write ELF header ---

    uint16_t text_idx = get_section_index_by_name(fd, ".text");

    new_ehdr.e_entry = new_shdr[text_idx].sh_addr;      // Entry point address
    new_ehdr.e_shoff = ALIGN_UP(off, 8);                // Start of section headers

    if (lseek(new_fd, 0, SEEK_SET) < 0) {
        printf("Error: lseek\n");
        return -1;
    }

    if (write(new_fd, &new_ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        printf("Error: writing ELF header\n");
        return -1;
    }

    // --- Write section headers ---

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

    // --- Copy program headers ---

    Elf64_Phdr new_phdr[new_ehdr.e_phnum];
    memcpy(new_phdr, phdr, ehdr.e_phnum * sizeof(Elf64_Phdr));

    // --- Modify program headers ---

    /* Update program header 0 */
    if(phdr[0].p_type == PT_PHDR) {
        new_phdr[0].p_filesz = phdr[0].p_filesz + sizeof(Elf64_Phdr);
        new_phdr[0].p_memsz = phdr[0].p_memsz + sizeof(Elf64_Phdr);
    }
    else {
        printf("Error: the first program header is not PT_PHDR\n");
        return -1;
    }

    /* Update the following original program headers */
    for (uint16_t i = 1; i < ehdr.e_phnum; i++) {
        if(seg2sec[i].sec_num == 0) {
            continue;
        }

        uint16_t num = seg2sec[i].sec_num;

        new_phdr[i].p_offset = new_shdr[seg2sec[i].sec_idx[0]].sh_offset;
        new_phdr[i].p_vaddr = new_shdr[seg2sec[i].sec_idx[0]].sh_addr;
        new_phdr[i].p_paddr = new_shdr[seg2sec[i].sec_idx[0]].sh_addr;
        new_phdr[i].p_filesz = new_shdr[seg2sec[i].sec_idx[num - 1]].sh_offset + new_shdr[seg2sec[i].sec_idx[num - 1]].sh_size - new_shdr[seg2sec[i].sec_idx[0]].sh_offset;
        new_phdr[i].p_memsz = new_shdr[seg2sec[i].sec_idx[num - 1]].sh_addr + new_shdr[seg2sec[i].sec_idx[num - 1]].sh_size - new_shdr[seg2sec[i].sec_idx[0]].sh_addr;
    }

    /* Update the program header of trampoline section*/
    new_phdr[ehdr.e_phnum].p_type = PT_LOAD;
    new_phdr[ehdr.e_phnum].p_flags = PF_X | PF_W;
    new_phdr[ehdr.e_phnum].p_offset = new_shdr[ehdr.e_shnum].sh_offset;
    new_phdr[ehdr.e_phnum].p_vaddr = new_shdr[ehdr.e_shnum].sh_addr;
    new_phdr[ehdr.e_phnum].p_paddr = new_shdr[ehdr.e_shnum].sh_addr;
    new_phdr[ehdr.e_phnum].p_filesz = section_size;
    new_phdr[ehdr.e_phnum].p_memsz = section_size;
    new_phdr[ehdr.e_phnum].p_align = section_align;

    // --- Write program headers ---

    for (uint16_t i = 0; i < new_ehdr.e_phnum; i++) {
        if (lseek(new_fd, sizeof(Elf64_Ehdr) + i * sizeof(Elf64_Phdr), SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (write(new_fd, &new_phdr[i], sizeof(Elf64_Phdr)) != sizeof(Elf64_Phdr)) {
            printf("Error: writing program header\n");
            return -1;
        }
    }
    
    // --- Close files ---

    free_seg2sec_mapping(seg2sec, &ehdr);
    close(fd);
    close(new_fd);

    return trampoline_addr;
}