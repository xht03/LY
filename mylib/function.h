#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>


int read_elf_header(int fd, Elf64_Ehdr *ehdr);
int read_program_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
int read_section_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);
int read_string_table(int fd, Elf64_Ehdr *ehdr, char *shstrtab);

char* read_section_by_index(int fd, uint16_t index);

uint16_t get_section_index_by_name(int fd, char *section_name);

void print_elf_header(Elf64_Ehdr *ehdr);
void print_program_headers(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
void print_section_headers(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);

int copy_elf_header(int new_fd, Elf64_Ehdr *ehdr);
int copy_sections(int fd, int new_fd, uint16_t shnum, Elf64_Shdr *shdr);
int copy_elf_file(char *filename, char *new_filename);





uint64_t get_free_vspace(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, uint64_t size, uint64_t align);

uint64_t create_trampoline_section(int fd, int new_fd, char *section_name, uint16_t section_size);
