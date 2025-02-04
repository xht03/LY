#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>


int read_elf_header(int fd, Elf64_Ehdr *ehdr);

void print_elf_header(Elf64_Ehdr *ehdr);

int read_program_headers(int fd, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);

void print_program_headers(Elf64_Ehdr *ehdr, Elf64_Phdr *phdr);
