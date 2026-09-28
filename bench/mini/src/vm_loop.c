#include <stdio.h>
#include <string.h>

/* A tiny bytecode interpreter: eight opcodes dispatched through a handler table.
   The bytecode transforms the input in three passes and compares it with `expected`.
   Each pass is a 3-opcode loop (LOAD/LOADO, an arithmetic op, STOREJ), so one iteration is
   at most 13 translation blocks at -O0 and trace_run folds it as (...)×n. */

struct vm {
    const unsigned char *code;
    unsigned pc;
    unsigned char acc;
    unsigned i;
    unsigned n;
    const unsigned char *in;
    unsigned char out[64];
};

static int op_halt  (struct vm *v) { (void)v; return 0; }
static int op_load  (struct vm *v) { v->acc = v->in[v->i]; return 1; }                        /* acc = in[i]   */
static int op_loado (struct vm *v) { v->acc = v->out[v->i]; return 1; }                       /* acc = out[i]  */
static int op_xor   (struct vm *v) { v->acc ^= v->code[v->pc++]; return 1; }                  /* acc ^= imm    */
static int op_add   (struct vm *v) { v->acc += v->code[v->pc++]; return 1; }                  /* acc += imm    */
static int op_rol   (struct vm *v) { unsigned r = v->code[v->pc++] & 7;                       /* acc = rol(acc, imm) */
                                     v->acc = (unsigned char)((v->acc << r) | (v->acc >> (8 - r))); return 1; }
static int op_storej(struct vm *v) { unsigned t = v->code[v->pc++];                           /* out[i++] = acc; if (i < n) pc = imm */
                                     v->out[v->i++] = v->acc; if (v->i < v->n) v->pc = t; return 1; }
static int op_reset (struct vm *v) { v->i = 0; return 1; }                                    /* i = 0 */

static int (*const handlers[8])(struct vm *) = {
    op_halt, op_load, op_loado, op_xor, op_add, op_rol, op_storej, op_reset
};

/* pass 1: out[i] = rol(in[i], 3) ; pass 2: out[i] ^= 0x5A ; pass 3: out[i] += 0x17 */
static const unsigned char program[] = {
    1, 5, 3, 6, 0,          /*  0: LOAD  ; ROL 3    ; STOREJ 0  */
    7,                      /*  5: RESET                        */
    2, 3, 0x5A, 6, 6,       /*  6: LOADO ; XOR 0x5A ; STOREJ 6  */
    7,                      /* 11: RESET                        */
    2, 4, 0x17, 6, 12,      /* 12: LOADO ; ADD 0x17 ; STOREJ 12 */
    0                       /* 17: HALT                         */
};

/* "DH{vm_l00p_tr4ce}" after the three passes */
static const unsigned char expected[17] = {
    0x8f, 0x2f, 0x98, 0x00, 0x48, 0xb7, 0x50, 0xf2, 0xf2,
    0xf0, 0xb7, 0x10, 0xe0, 0x12, 0x58, 0x88, 0xc8
};

static void run_vm(struct vm *v) {
    for (;;) {
        unsigned char op = v->code[v->pc++];
        if (!handlers[op & 7](v)) break;
    }
}

int main(void) {
    char buf[64];
    struct vm v;
    printf("Input: ");
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strlen(buf) != sizeof expected) { puts("Wrong"); return 1; }
    memset(&v, 0, sizeof v);
    v.code = program;
    v.in = (const unsigned char *)buf;
    v.n = (unsigned)sizeof expected;
    run_vm(&v);
    if (memcmp(v.out, expected, sizeof expected) != 0) { puts("Wrong"); return 1; }
    puts("Correct!");
    return 0;
}
