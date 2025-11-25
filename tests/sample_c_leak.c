#include <stdlib.h>

void leak_again() {
    char *p = malloc(256); // memory_leak
}
