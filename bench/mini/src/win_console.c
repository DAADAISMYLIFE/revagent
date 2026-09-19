#include <stdio.h>
#include <string.h>
/* "DH{w1ne_c0ns0le}" xor 0x33 */
static const unsigned char expected[16] = {
    0x77,0x7b,0x48,0x44,0x02,0x5d,0x56,0x6c,0x50,0x03,0x5d,0x40,0x03,0x5f,0x56,0x4e
};
int main(void) {
    char buf[64];
    printf("Input: "); fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;
    if (strlen(buf) != 16) { puts("Wrong"); return 1; }
    for (int i = 0; i < 16; i++) if ((unsigned char)(buf[i] ^ 0x33) != expected[i]) { puts("Wrong"); return 1; }
    puts("Correct!");
    return 0;
}
