# BDSec CTF 2026 -- The Bytecode Vault (Reverse Engineering)

## Challenge Overview

The binary prompts the user for a flag and validates it through a small
virtual-machine style dispatcher rather than a straightforward sequence
of checks. The VM executes four encoded opcodes stored in `.rodata`,
making the control flow appear more complex than it actually is.

## Static Analysis

The entry point performs the following operations:

1.  Read user input.
2.  Strip the trailing newline.
3.  Require an exact input length of **50 bytes (0x32)**.
4.  Execute four VM instructions encoded in `DAT_001022f2`.

The encoded VM program is:

  Encoded   XOR Key   Opcode
  --------- --------- -------------------
  B4        A5        11 (Length Check)
  81        B6        37 (Transform)
  AC        C7        6B (Compare)
  38        D8        E0 (Success)

Thus the VM executes:

    CHECK_LENGTH
    TRANSFORM
    COMPARE
    SUCCESS

## Input Transformation

For each character `flag[i]`:

``` c
xor_key = 0x41 + 0x1d * i;

t = flag[i] ^ xor_key;

rot = ((i % 7) + 1) & 7;

t = ROL8(t, rot);

t += (0x17 ^ (0x0b * i));

output[(17 * i) % 50] = t;
```

The transformed bytes are stored in a permuted output buffer.

## Comparison

The reference table is stored at `DAT_001022c0`.

Before comparison, each byte is decoded:

``` c
expected[(17*i)%50] =
DAT_001022c0[i] ^ ((0x44 + 13*i) & 0xff);
```

The transformed user buffer must exactly match this decoded table.

## Reversing the Algorithm

Since every operation is reversible:

1.  Decode the reference table.
2.  Undo the additive constant.
3.  Rotate right.
4.  Undo the XOR.

Reverse equations:

``` python
expected = dat[i] ^ ((0x44 + 13*i) & 0xff)

tmp = (expected - (0x17 ^ (11*i))) & 0xff

tmp = ror8(tmp, ((i % 7)+1)&7)

flag[i] = tmp ^ ((0x41 + 29*i) & 0xff)
```

## Solver

``` python
def ror8(x, r):
    return ((x >> r) | ((x << (8-r)) & 0xff)) & 0xff

dat = [
0x59,0xD5,0x1C,0x78,0x61,0x0F,0x09,0x4D,0xC0,0xBD,
0x4C,0x57,0xE7,0x67,0x0A,0x13,0xA4,0x60,0x7D,0x27,
0x0E,0xBE,0x71,0x69,0x04,0x61,0x9F,0x66,0xF1,0x1A,
0x31,0x2C,0x03,0x94,0xE6,0xA7,0x6B,0xB7,0x41,0x92,
0x18,0x4C,0x59,0x69,0xE5,0xC5,0x8A,0x9C,0x5D,0xB2
]

flag = bytearray(50)

for i in range(50):
    expected = dat[i] ^ ((0x44 + 13*i) & 0xff)
    tmp = (expected - (0x17 ^ (11*i))) & 0xff
    tmp = ror8(tmp, ((i % 7)+1)&7)
    flag[i] = tmp ^ ((0x41 + 29*i) & 0xff)

print(flag.decode())
```

## Flag

    BDSEC{c0nTr0L_fl0w_1s_4_l13_bUt_bYt3c0d3_d03s_n0t}
