#include <stdio.h>
#include <stdlib.h>

void win(int a, int b) {
    if (a == 0xdeadbeef && b == 0x1337c0de) {
        printf("Congratz! Cat the flag and sent it to @deluqs in the Discord\n");
        system("/bin/sh");
        exit(0);
    }
    return;
}

int vuln() {
    int b;
    char buffer[40];
    b = 0;
    printf("Can you exploit this?\n");
    gets(&buffer);
    return b;
}

void main() {
    vuln();
    printf("You did not exploit it.\n");
    return;
}