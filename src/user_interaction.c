#include "user_interaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <capstone/capstone.h>

void print_logo() {
    const char* figlet = 
        "   ______       ______  ____  ____ \n"
        "  / ___/ |     / / __ \\/ __ \\/ __ \\\n"
        "  \\__ \\| | /| / / / / / /_/ / / / /\n"
        " ___/ /| |/ |/ / /_/ / _, _/ /_/ / \n"
        "/____/ |__/|__/\\____/_/ |_/_____/  \n";
    printf("%s\n", figlet);
}

void print_usage(char* program_name) {
    fprintf(stderr, "%s Usage:\n", program_name);
    fprintf(stderr, "\t-h Print the help message\n");
    fprintf(stderr, "\t-e Print the file entropy\n");
    fprintf(stderr, "\t-d Print disassembly\n");
    fprintf(stderr, "\t-f Set disassembly flavor [intel|att]\n");
    fprintf(stderr, "\t-l Print logo\n");
    fprintf(stderr, "\t-a Print all section data\n");
    fprintf(stderr, "\t-s <section> Print section data\n");
    fprintf(stderr, "\t-c <filename> Compress the file into <filename>\n");
    fprintf(stderr, "\t-i <filename> Inflate the file into <filename>\n");
}

int get_disassembly_flavor(char* string) {
    if (strcmp(string, "intel") == 0)
        return CS_OPT_SYNTAX_INTEL;
    else if (strcmp(string, "att") == 0)
        return CS_OPT_SYNTAX_ATT;
    fprintf(stderr, "%s is not a valid disassembly flavor (intel|att)\n", string);
    exit(EXIT_FAILURE);
}

struct program_flags *get_flags(int argc, char *argv[]) {
    int opt;
    struct program_flags *flags = malloc(sizeof(struct program_flags));
    extern char *optarg;
    while ((opt = getopt(argc, argv, "lef:dshcia")) != -1) {
        switch (opt) {
            case 'l':
                print_logo();
                break;
            case 'e':
                flags->entropy_flag = 1;
                break;
            case 'd':
                flags->disassembly_flag = 1;
                break;
            case 'f':
                flags->disassembly_flavor = get_disassembly_flavor(optarg);
                break;
            case 's':
                printf("Option 's'\n");
                break;
            case 'a':
                flags->all_flag = 1;
                break;
            case 'i':
                flags->compression_flag = 1;
                break;
            case 'c':
                flags->compression_flag = 2;
                break;
            case 'h':
            case '?':
                print_usage(argv[0]);
                free(flags);
                exit(EXIT_FAILURE);
        }
    }
    return flags;
}