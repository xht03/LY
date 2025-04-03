#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

#include "function.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
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
    // for(int i = 0; i < shnum; i++) {
    //     printf("Section %d: %s\n", i, shstrtab + shdr[i].sh_name);
    // }

    return shstrtab;
}

int read_dynamic_section(int fd, Elf64_Dyn **dyn)
{
    Elf64_Ehdr ehdr;
    read_elf_header(fd, &ehdr);

    Elf64_Shdr shdr[ehdr.e_shnum];
    read_section_headers(fd, &ehdr, shdr);

    uint16_t dyn_idx = get_section_index_by_name(fd, ".dynamic");
    uint16_t entry_num = shdr[dyn_idx].sh_size / shdr[dyn_idx].sh_entsize;  // There may be some invalid entries at the end
    uint16_t dyn_num = 0;   // Number of valid entries

    *dyn = (Elf64_Dyn *)malloc(entry_num * sizeof(Elf64_Dyn));

    for (uint16_t i = 0; i < entry_num; i++) {
        if (lseek(fd, shdr[dyn_idx].sh_offset + i * shdr[dyn_idx].sh_entsize, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (read(fd, &(*dyn)[i], sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
            printf("Error: reading dynamic section\n");
            return -1;
        }

        dyn_num++;

        if ((*dyn)[i].d_tag == DT_NULL) {
            break;
        }
    }
    return dyn_num;
}

void print_dynamic_section(Elf64_Dyn *dyn, uint16_t dyn_num)
{
    printf("Dynamic Section:\n");
    printf("Number of entries: %d\n", dyn_num);
    for (uint16_t i = 0; i < dyn_num; i++) {
        printf("  Tag:               0x%lx\n", dyn[i].d_tag);
        printf("  Value:             %lu\n", dyn[i].d_un.d_val);
        printf("  Pointer:           0x%lx\n", dyn[i].d_un.d_ptr);
        printf("--------------------------\n");
    }
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

uint64_t get_max_vaddr(Elf64_Shdr *shdr, uint16_t shnum)
{
    uint64_t max_vaddr = 0;

    for (uint16_t i = 0; i < shnum; i++) {
        if (shdr[i].sh_addr + shdr[i].sh_size > max_vaddr) {
            max_vaddr = shdr[i].sh_addr + shdr[i].sh_size;
        }
    }

    return max_vaddr;
}


uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size)
{
    /**
     * @brief Create a trampoline section at the end of the elf file. Return the virtual address of the trampoline section.
     * 
     * @note The trampoline section must be loadable into memory and executable.
     */

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
     * 1. number of section headers + 1
     * 2. number of program headers + 1
     * 3. adjust start of section headers
     */

    Elf64_Ehdr new_ehdr = ehdr;
    new_ehdr.e_shnum += 1;
    new_ehdr.e_phnum += 1;
    
    uint64_t old_sections_end = shdr[ehdr.e_shnum - 1].sh_offset + shdr[ehdr.e_shnum - 1].sh_size + strlen(section_name) + 1;
    uint64_t tramp_offset = ALIGN_UP(old_sections_end, 4096);

    new_ehdr.e_shoff = ALIGN_UP(tramp_offset + section_size, 8);


    // --- Create new section headers ---
    /**
     * @brief 
     * 1. Copy all old section headers
     * 2. Adjust the offsets of section headers before .init
     * 2. Extend the section header string table
     * 3. Add the new section header
     */

    Elf64_Shdr new_shdr[ehdr.e_shnum + 1];

    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        new_shdr[i] = shdr[i];
    }

    uint16_t initIdx = get_section_index_by_name(fd, ".init");

    new_shdr[1].sh_offset = shdr[1].sh_offset + sizeof(Elf64_Phdr);
    new_shdr[1].sh_addr = phdr[1].p_vaddr + sizeof(Elf64_Phdr);
    for (uint16_t i = 2; i < initIdx; i++) {
        new_shdr[i].sh_offset = ALIGN_UP(new_shdr[i - 1].sh_offset + new_shdr[i - 1].sh_size, new_shdr[i].sh_addralign);
        new_shdr[i].sh_addr = ALIGN_UP(new_shdr[i - 1].sh_addr + new_shdr[i - 1].sh_size, new_shdr[i].sh_addralign);
    }

    if (new_shdr[initIdx - 1].sh_offset +  new_shdr[initIdx - 1].sh_size > new_shdr[initIdx].sh_offset) {
        printf("Error: no space for new program header.\n");
        return -1;
    }

    new_shdr[ehdr.e_shstrndx].sh_size += strlen(section_name) + 1;

    new_shdr[ehdr.e_shnum].sh_name = shdr[ehdr.e_shstrndx].sh_size;
    new_shdr[ehdr.e_shnum].sh_type = SHT_PROGBITS;
    new_shdr[ehdr.e_shnum].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_shdr[ehdr.e_shnum].sh_addr = ALIGN_UP(get_max_vaddr(new_shdr, ehdr.e_shnum), 0x1000);
    new_shdr[ehdr.e_shnum].sh_offset = tramp_offset;
    new_shdr[ehdr.e_shnum].sh_size = section_size;
    new_shdr[ehdr.e_shnum].sh_link = 0;
    new_shdr[ehdr.e_shnum].sh_info = 0;
    new_shdr[ehdr.e_shnum].sh_addralign = 16;
    new_shdr[ehdr.e_shnum].sh_entsize = 0;

    // --- Create new program headers ---
    /**
     * @brief
     * 1. Copy all old program headers
     * 2. Keep vaddr unchanged, but adjust offset
     * 3. Add a new program header
     */
    Elf64_Phdr new_phdr[ehdr.e_phnum + 1];

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        new_phdr[i] = phdr[i];
    }

    new_phdr[0].p_filesz += sizeof(Elf64_Phdr);
    new_phdr[0].p_memsz += sizeof(Elf64_Phdr);

    for (uint16_t i = 1; i < ehdr.e_phnum; i++) {
        if (seg2sec[i].sec_num == 0) {
            continue;
        }

        uint64_t start_off = new_shdr[seg2sec[i].sec_idx[0]].sh_offset;
        uint64_t end_off = new_shdr[seg2sec[i].sec_idx[0]].sh_offset + shdr[seg2sec[i].sec_idx[0]].sh_size;

        uint64_t start_addr = new_shdr[seg2sec[i].sec_idx[0]].sh_addr;
        uint64_t end_addr = new_shdr[seg2sec[i].sec_idx[0]].sh_addr + shdr[seg2sec[i].sec_idx[0]].sh_size;

        for (uint16_t j = 0; j < seg2sec[i].sec_num; j++) {
            start_off = MIN(start_off, new_shdr[seg2sec[i].sec_idx[j]].sh_offset);
            end_off = MAX(end_off, new_shdr[seg2sec[i].sec_idx[j]].sh_offset + shdr[seg2sec[i].sec_idx[j]].sh_size);

            start_addr = MIN(start_addr, new_shdr[seg2sec[i].sec_idx[j]].sh_addr);
            end_addr = MAX(end_addr, new_shdr[seg2sec[i].sec_idx[j]].sh_addr + shdr[seg2sec[i].sec_idx[j]].sh_size);
        }

        new_phdr[i].p_offset = start_off;
        new_phdr[i].p_filesz = end_off - start_off;

        new_phdr[i].p_vaddr = start_addr;
        new_phdr[i].p_paddr = start_addr;
        new_phdr[i].p_memsz = end_addr - start_addr;
    }


    new_phdr[ehdr.e_phnum].p_type = PT_LOAD;
    new_phdr[ehdr.e_phnum].p_flags = PF_X | PF_R;
    new_phdr[ehdr.e_phnum].p_offset = tramp_offset;
    new_phdr[ehdr.e_phnum].p_vaddr = new_shdr[ehdr.e_shnum].sh_addr;
    new_phdr[ehdr.e_phnum].p_paddr = new_shdr[ehdr.e_shnum].sh_addr;
    new_phdr[ehdr.e_phnum].p_filesz = section_size;
    new_phdr[ehdr.e_phnum].p_memsz = section_size;
    new_phdr[ehdr.e_phnum].p_align = 4096;


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

    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        char *buf = (char *)malloc(shdr[i].sh_size);

        if (lseek(fd, shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }
        
        if (read(fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        if(lseek(new_fd, new_shdr[i].sh_offset, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }
        
        if(write(new_fd, buf, shdr[i].sh_size) != shdr[i].sh_size) {
            printf("Error: writing section\n");
            return -1;
        }

        free(buf);

        // Write the new section name into shstrtab
        if (i == ehdr.e_shstrndx) {
            if (lseek(new_fd, new_shdr[i].sh_offset + shdr[i].sh_size, SEEK_SET) < 0) {
                printf("Error: lseek\n");
                return -1;
            }

            if (write(new_fd, section_name, strlen(section_name) + 1) != strlen(section_name) + 1) {
                printf("Error: writing section\n");
                return -1;
            }
        }
    }

    // --- Adjust new dynamic section ---
    uint16_t dyn_idx = get_section_index_by_name(fd, ".dynamic");
    Elf64_Dyn *dyn = NULL;
    uint16_t dyn_num = read_dynamic_section(fd, &dyn);

    for (uint16_t i = 0; i < dyn_num; i++) {
        if (dyn[i].d_tag == DT_NULL) {
            break;
        }

        if (dyn[i].d_tag == DT_GNU_HASH) {
            uint16_t gnu_hash_idx = get_section_index_by_name(fd, ".gnu.hash");
            if (gnu_hash_idx == -1) {
                printf("Error: gnu hash section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[gnu_hash_idx].sh_addr;
        } 
        else if (dyn[i].d_tag == DT_STRTAB) {
            uint16_t dynstr_idx = get_section_index_by_name(fd, ".dynstr");
            if (dynstr_idx == -1) {
                printf("Error: dynstr section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[dynstr_idx].sh_addr;
        }
        else if (dyn[i].d_tag == DT_SYMTAB) {
            uint16_t dynsym_idx = get_section_index_by_name(fd, ".dynsym");
            if (dynsym_idx == -1) {
                printf("Error: dynsym section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[dynsym_idx].sh_addr;
        }
        else if (dyn[i].d_tag == DT_REL) {
            uint16_t rela_plt_idx = get_section_index_by_name(fd, ".rela.plt");
            if (rela_plt_idx == -1) {
                printf("Error: rela section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[rela_plt_idx].sh_addr;
        }
        else if (dyn[i].d_tag == DT_RELA) {
            uint16_t rela_dyn_idx = get_section_index_by_name(fd, ".rela.dyn");
            if (rela_dyn_idx == -1) {
                printf("Error: rela section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[rela_dyn_idx].sh_addr;
        }
        /*else if (dyn[i].d_tag == DT_RELASZ) {
            uint16_t rela_dyn_idx = get_section_index_by_name(fd, ".rela.dyn");
            if (rela_dyn_idx == -1) {
                printf("Error: rela section not found\n");
                return -1;
            }
            dyn[i].d_un.d_val = new_shdr[rela_dyn_idx].sh_size;
        }*/
        else if (dyn[i].d_tag == DT_VERNEED) {
            uint16_t gnu_version_r_idx = get_section_index_by_name(fd, ".gnu.version_r");
            if (gnu_version_r_idx == -1) {
                printf("Error: gnu version r section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[gnu_version_r_idx].sh_addr;
        }
        else if (dyn[i].d_tag == DT_VERSYM) {
            uint16_t gnu_version_idx = get_section_index_by_name(fd, ".gnu.version");
            if (gnu_version_idx == -1) {
                printf("Error: gnu version section not found\n");
                return -1;
            }
            dyn[i].d_un.d_ptr = new_shdr[gnu_version_idx].sh_addr;
        }
    }

    // Write new dynamic section
    for (uint16_t i = 0; i < dyn_num; i++) {
        if (lseek(new_fd, new_shdr[dyn_idx].sh_offset + i * new_shdr[dyn_idx].sh_entsize, SEEK_SET) < 0) {
            printf("Error: lseek\n");
            return -1;
        }

        if (write(new_fd, &dyn[i], sizeof(Elf64_Dyn)) != sizeof(Elf64_Dyn)) {
            printf("Error: writing dynamic section\n");
            return -1;
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
    
    return new_phdr[ehdr.e_phnum].p_vaddr;
}