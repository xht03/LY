#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

typedef struct {
    uint16_t sec_num;       // Number of sections in the section list
    uint16_t *sec_idx;      // Indices of sections in the section list
} SecList;


int read_elf_header(int fd, Elf64_Ehdr *ehdr);
int read_program_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
int read_section_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);
char* read_string_table(int fd, Elf64_Ehdr *ehdr);

char* read_section_by_index(int fd, uint16_t index);

uint16_t get_section_index_by_name(int fd, char *section_name);

SecList* get_seg2sec_mapping(int fd);
int free_seg2sec_mapping(SecList *seg2sec, Elf64_Ehdr *ehdr);

void print_elf_header(Elf64_Ehdr *ehdr);
void print_program_headers(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
void print_section_headers(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);

int copy_elf_header(int new_fd, Elf64_Ehdr *ehdr);
int copy_sections(int fd, int new_fd, uint16_t shnum, Elf64_Shdr *shdr);
int copy_elf_file(char *filename, char *new_filename);

uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size);
