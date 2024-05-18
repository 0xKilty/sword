#include "entropy.h"

float calculate_entropy(int* occurrences, int total_count) {
    float entropy = 0;
    for (int i = 0; i < ENTROPY_BUFFER_SIZE; i++) {
        float probability = (float)occurrences[i] / total_count;
        if (probability > 0)
            entropy += probability * log2f(probability);
    }
    return -entropy;
}

void get_frequencies(int fd, int *frequencies, int *total_count) {
    char byte;
    ssize_t bytesRead;

    lseek(fd, 0, SEEK_SET);
    while ((bytesRead = read(fd, &byte, 1)) > 0) {
        frequencies[(unsigned char)byte]++;
        (*total_count)++;
    }
    lseek(fd, 0, SEEK_SET);
}

float calculate_fd_entropy(int fd) {
    int frequencies[ENTROPY_BUFFER_SIZE] = {0};
    int total_count = 0;
    get_frequencies(fd, frequencies, &total_count);
    return calculate_entropy(frequencies, total_count);
}