#include <stdio.h>
#include <string.h>

/* "DH{x0r_m1n1_ch3ck}" xor 0x5A */
static const unsigned char expected[18] = {
    0x1e, 0x12, 0x21, 0x22, 0x6a, 0x28, 0x05, 0x37, 0x6b,
    0x34, 0x6b, 0x05, 0x39, 0x32, 0x69, 0x39, 0x31, 0x27
};

int main(void) {
    char buf[64];
    printf("Input: ");
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strlen(buf) != sizeof expected) { puts("Wrong"); return 1; }
    for (size_t i = 0; i < sizeof expected; i++) {
        if ((unsigned char)(buf[i] ^ 0x5A) != expected[i]) { puts("Wrong"); return 1; }
    }
    puts("Correct!");
    return 0;
}
