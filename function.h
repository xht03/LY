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


void print_elf_header(Elf64_Ehdr *ehdr);
void print_program_headers(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
void print_section_headers(Elf64_Ehdr *ehdr, Elf64_Shdr *shdr);

int copy_sections(int fd, int new_fd, uint16_t shnum, Elf64_Shdr *shdr);

int copy_elf_file(char *filename, char *new_filename);
