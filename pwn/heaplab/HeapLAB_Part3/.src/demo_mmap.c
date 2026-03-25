#include <stdio.h>
#include <stdlib.h>

int main(void) {

    void* a = malloc(0x20ff8);
    void* b = malloc(0x20fe8);

    free(a);

    void* c = malloc(0x1fffe8);

    return 0;
}
