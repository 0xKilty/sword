#include "compression.h"
#include "entropy.h"
#include <stdio.h>

int inflate(int fd) {
    printf("Inflating\n");
    return 0;
}

int compress(int fd) {
    int frequencies[ENTROPY_BUFFER_SIZE] = {0};
    int total_count = 0;
    get_frequencies(fd, frequencies, &total_count);
    for (int i = 0; i < ENTROPY_BUFFER_SIZE; i++) {
        printf("%d %d\n", i, frequencies[i]);
    }
    return 0;
}