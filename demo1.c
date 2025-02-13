#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <bfd.h>
#include <elf.h>

#include "mylib/function.h"

/**
 * @brief Example of creating a trampoline section in an ELF file
 */

int main()
{
    char filename[50] = "/home/keats/LY/bin/hello";
    char new_filename[50] = "/home/keats/LY/bin/hello_tramp";

    int fd = open(filename, O_RDONLY);
    int new_fd = open(new_filename, O_RDWR | O_CREAT, 0666);
    
    if (fd < 0 || new_fd < 0) {
        printf("Error: opening file\n");
        return -1;
    }

    uint64_t off  = create_trampoline_section(fd, new_fd, ".tramp", 0x1000, 16);

    printf("Trampoline section created at 0x%lx\n", off);

    close(fd);
    return 0;
}