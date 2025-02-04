#include <stdio.h>
#include <bfd.h>
#include <stdlib.h>
#include <string.h>

// Function to dump section details for debugging
void dump_section(bfd *abfd, asection *sect, void *obj) {
    printf("Section: %s\n", bfd_section_name(sect));
    printf("  Size: %lx\n", (long) bfd_section_size(sect));
    printf("  VMA: %lx\n", (long) bfd_section_vma(sect));
}

// Function to copy a section from the input file to the output file
void copy_section(bfd *abfd, bfd *obfd, asection *sect) {
    const char *section_name = bfd_section_name(sect);
    long size = bfd_section_size(sect);

    if (size > 0) {
        char *content = malloc(size);
        if (content == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            return;
        }

        // Read the section's content from the input ELF
        if (!bfd_get_section_contents(abfd, sect, content, 0, size)) {
            fprintf(stderr, "Failed to read section contents\n");
            free(content);
            return;
        }

        // Create a new section in the output ELF file with the same name
        asection *newsect = bfd_make_section_anyway(obfd, section_name);
        if (newsect == NULL) {
            fprintf(stderr, "Failed to create section %s in output file: %s\n", section_name, bfd_errmsg(bfd_get_error()));
            free(content);
            return;
        }

        // Set the flags and size for the new section
        bfd_set_section_flags(newsect, bfd_section_flags(sect));
        bfd_set_section_size(newsect, size);
        bfd_set_section_vma(newsect, bfd_section_vma(sect));

        // Write the content of the section to the new ELF file
        if (!bfd_set_section_contents(obfd, newsect, content, 0, size)) {
            fprintf(stderr, "Failed to write section contents\n");
        }

        free(content);
        printf("Section %s copied successfully\n", section_name);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <input_filename> <output_filename>\n", argv[0]);
        return 1;
    }

    const char *input_filename = argv[1];
    const char *output_filename = argv[2];

    // Initialize the BFD library
    bfd_init();

    // Open the input ELF file
    bfd *abfd = bfd_openr(input_filename, NULL);
    if (abfd == NULL) {
        bfd_perror("Error opening input file");
        return 1;
    }

    // Check if the input file is a valid ELF object file
    if (!bfd_check_format(abfd, bfd_object)) {
        bfd_perror("Not a valid object file");
        bfd_close(abfd);
        return 1;
    }

    // Print sections of the ELF file for debugging
    printf("Original ELF file sections:\n");
    bfd_map_over_sections(abfd, dump_section, NULL);

    // Create a new output file to write the modified ELF
    bfd *obfd = bfd_openw(output_filename, bfd_get_target(abfd));
    if (obfd == NULL) {
        bfd_perror("Error creating output file");
        bfd_close(abfd);
        return 1;
    }

    // Set the architecture and machine type of the output file
    if (!bfd_set_format(obfd, bfd_get_format(abfd))) {
        bfd_perror("Error setting format");
        bfd_close(abfd);
        bfd_close(obfd);
        return 1;
    }

    // Counter for ensuring that at least 2 sections are copied
    int copied_sections = 0;

    // Iterate over sections and copy at least 2 sections
    for (asection *sect = abfd->sections; sect != NULL; sect = sect->next) {
        const char *section_name = bfd_section_name(sect);
        if (strcmp(section_name, ".text") == 0 || strcmp(section_name, ".data") == 0) {
            copy_section(abfd, obfd, sect);
            copied_sections++;
        }

        // Stop after copying at least 2 sections
        if (copied_sections >= 2) {
            break;
        }
    }

    if (copied_sections < 2) {
        printf("Warning: Less than 2 sections were copied\n");
    }

    // Close input and output files
    if (!bfd_close(abfd)) {
        bfd_perror("Error closing input file");
        return 1;
    }

    if (!bfd_close(obfd)) {
        bfd_perror("Error closing output file");
        return 1;
    }

    printf("Modified ELF file saved as: %s\n", output_filename);
    return 0;
}