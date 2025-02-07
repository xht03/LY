#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

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

uint64_t get_free_vspace(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, uint64_t size, uint64_t align)
{
    /**
     * @brief Get the free virtual space in the ELF file.
     * 
     * @note The virtual space must be aligned.
     */

    uint16_t phnum = ehdr->e_phnum;         // Number of program headers
    Elf64_Phdr temp_phdr[phnum];            // Temporary program header table

    memcpy(temp_phdr, phdr, phnum * sizeof(Elf64_Phdr));
    sort_phdr_by_vaddr(temp_phdr, phnum);

    // Merge used intervals and try to find the free space between them
    uint64_t start = temp_phdr[0].p_vaddr;
    uint64_t end = temp_phdr[0].p_vaddr + temp_phdr[0].p_memsz;

    for (uint16_t i = 0; i < phnum; i++) {
        if (temp_phdr[i].p_type & PT_LOAD) {
            uint64_t seg_start = temp_phdr[i].p_vaddr;
            uint64_t seg_end = temp_phdr[i].p_vaddr + temp_phdr[i].p_memsz;

            if (seg_start <= end) {
                end = MAX(end, seg_end);
            }
            else {
                if (size <= seg_start - end) {
                    uint64_t v_start = ALIGN_UP(end, align);
                    uint64_t v_end = v_start + size;

                    if (v_end <= seg_start) {
                        return v_start;
                    }
                }

                end = seg_end;
            }    
        }
    }

    // If the free space is at the end of the file
    return ALIGN_UP(end, align);
}



uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size)
{
    /**
     * @brief Create a trampoline section at the end of the elf file.
     * 
     * @note The trampoline section must be loadable into memory and executable.
     */


    // --- Modify elf header ---
    Elf64_Ehdr ehdr;
    Elf64_Ehdr new_ehdr;

    read_elf_header(fd, &ehdr);
    memcpy(&new_ehdr, &ehdr, sizeof(Elf64_Ehdr));

    if(section_size % 16 != 0) {
        printf("Error: section size must be aligned.\n");
        close(fd);
        close(new_fd);
        return -1;
    }   // not sure

    new_ehdr.e_phnum += 1;
    new_ehdr.e_shoff += section_size;
    new_ehdr.e_shnum += 1;

    copy_elf_header(new_fd, &new_ehdr);

    // --- Add a new program header ---

    uint64_t phoff = ehdr.e_phoff;      // Start of program headers
    uint16_t phnum = ehdr.e_phnum;      // Number of program headers

    Elf64_Phdr phdr[phnum];             // Program header (56 byte each entry)
    Elf64_Phdr new_phdr[phnum + 1];

    read_program_headers(fd, &ehdr, phdr);

    for (uint16_t i = 0; i < phnum; i++) {
        memcpy(&new_phdr[i], &phdr[i], sizeof(Elf64_Phdr));
    }

    // --- Move the sections before the .init section ---
    

    // --- Modify the new program header ---

    new_phdr[phnum].p_type = PT_LOAD;
    new_phdr[phnum].p_flags = PF_X | PF_R;
    new_phdr[phnum].p_offset = ALIGN_UP(ehdr.e_shoff, 0x1000);
    new_phdr[phnum].p_vaddr = get_free_vspace(&ehdr, phdr, section_size, 0x1000);
    new_phdr[phnum].p_paddr = new_phdr[phnum].p_vaddr;
    new_phdr[phnum].p_filesz = section_size;
    new_phdr[phnum].p_memsz = section_size;
    new_phdr[phnum].p_align = 0x1000;           // code alignment

    





}