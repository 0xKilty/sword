#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>

const char str[] = "Hello from the .rodata section\n";

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <num>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int n = atoi(argv[1]);

    bool *prime = (bool *) malloc((n + 1) * sizeof(bool));

    memset(prime, true, (n + 1) * sizeof(*prime));
 
    for (int p = 2; p * p <= n; p++) {
        if (prime[p] == true) {
            for (int i = p * p; i <= n; i += p)
                prime[i] = false;
        }
    }

    printf("%s", str);

    for (int p = 2; p <= n; p++)
        if (prime[p])
            printf("%d\n",p);

    free(prime);

    return 0;
}