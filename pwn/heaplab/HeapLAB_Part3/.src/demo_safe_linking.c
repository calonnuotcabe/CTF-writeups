#include <stdio.h>
#include <stdlib.h>

int main(void) {

    void* a = malloc(0x18);
    void* b = malloc(0x18);

    free(a);
    free(b);

    return 0;
}
