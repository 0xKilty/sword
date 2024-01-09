#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: <filename>\n");
        return 1;
    }

    FILE *file;
    char *filename = argv[1];

    file = fopen(filename, "r");
    if (file == NULL) {
        printf("File: (%s) does not exist or can not be opened.\n", filename);
        return 1;
    }

    fclose(file);
    return 0;
}