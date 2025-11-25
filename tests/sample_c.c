#include <stdio.h>
#include <stdlib.h>

void leak() {
    char *p = (char*)malloc(100); // memory_leak
}

void overflow(char *src) {
    char buf[10];
    strcpy(buf, src); // buffer_overflow
}

int main() {
    int x = 1;
    if (x == 1) {
        printf("test\n");
    }
    return 0;
}
