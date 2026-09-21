KEY = [0x13, 0x37, 0x42, 0x99]


def transform(x):
    return [(x[i] ^ KEY[i % len(KEY)]) & 0xff for i in range(len(x))]
