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
    char filename[50] = "/home/keats/LY/bin/hello";
    char new_filename[50] = "/home/keats/LY/bin/output";

    if (copy_elf_file(filename, new_filename) < 0) {
        printf("Error: copying ELF file\n");
        return -1;
    }

    return 0;
}