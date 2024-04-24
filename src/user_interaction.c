#include "user_interaction.h"
#include <stdio.h>

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
    fprintf(stderr, "\t-s <section> Print section data\n");
}