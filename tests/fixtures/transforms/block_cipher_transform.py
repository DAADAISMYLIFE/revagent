# 8-byte block: 16 rounds x 8 steps of acc = rol3(SBOX[acc ^ KEY[i]] + p[(i+1)&7]); p[(i+1)&7] = acc
KEY = list(b"I_am_KEY")


def _aes_sbox():
    def rotl(v, k):
        return ((v << k) | (v >> (8 - k))) & 0xff

    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff
        if q & 0x80:
            q ^= 0x09
        x = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)
        sbox[p] = (x ^ 0x63) & 0xff
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = Table(_aes_sbox())   # Table is injected by solve_check; on the host it is a plain list wrapper


def rol3(v):
    return ((v << 3) | (v >> 5)) & 0xff


def transform(x):
    out = []
    for b in range(0, len(x), 8):
        p = list(x[b:b + 8])
        acc = p[0]
        for _ in range(16):
            for i in range(8):
                v = (SBOX[acc ^ KEY[i]] + p[(i + 1) & 7]) & 0xff
                acc = rol3(v)
                p[(i + 1) & 7] = acc
        out.extend(p)
    return out
