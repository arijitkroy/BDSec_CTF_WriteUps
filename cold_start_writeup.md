# CTF Writeup: `cold_start`

## Challenge Overview

| Field | Details |
| :--- | :--- |
| **Challenge Name** | `cold_start` |
| **Category** | Reverse Engineering |
| **Target Binary** | `cold_start` (Linux 64-bit ELF executable, PIE, stripped) |
| **Input Format** | 6-character hexadecimal string (`0 <= seed < 0x1000000`) |
| **Valid Activation Seed** | `93C7A4` |
| **Recovered Flag** | `BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}` |

---

## 1. Initial Binary Analysis

Running static binary inspection:

```bash
$ file cold_start
cold_start: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., stripped
```

Key characteristics:
* The binary is **stripped** (symbol names removed).
* The entry point `_start` sets up GLIBC initialization and transfers execution to `main` at `0x001010d0`.
* The program prompts for an **activation seed**: a 6-character hex string parsed via `strtoul(input, NULL, 16)`.
* Constraints on input:
  1. Input string length must be exactly 6 characters.
  2. Parsed numeric value must fit in 24 bits ($0 \le \text{seed} \le \text{0xFFFFFF}$).

---

## 2. Reverse Engineering the Verifier Engine

### Function & Data Mapping

| VMA Address Range | Identification | Description |
| :--- | :--- | :--- |
| `0x001010d0 - 0x0010156f` | `main` / Verifier | CLI prompt, state mixing (96 rounds), 3 verification checks, and flag decryptor. |
| `0x00102140 - 0x0010253f` | `state_mixing_lut` | 256-entry `uint32_t` non-linear substitution table in `.rodata`. |
| `0x00102100 - 0x00102129` | `flag_enc_table` | 42-byte ciphertext payload table in `.rodata`. |

---

### Phase I: State Machine Initialization & 96-Round Mixing

The verifier initializes state variables using the 24-bit input `seed`:

$$\begin{aligned}
\text{edi}_0 &= \text{ROL32}(\text{seed} \times \text{0x9E3779B1}, 7) \oplus \text{0x1B873593} \\
\text{edx}_0 &= (\text{seed} \ll 5) \oplus (\text{seed} \gg 3) \oplus \text{0x811C9DC5} \\
\text{r8d}_0 &= \text{seed} \oplus \text{0xA3C59AC3} \\
\text{r9d}_0 &= 0, \quad \text{r10d}_0 = 0, \quad \text{r11d}_0 = 0
\end{aligned}$$

#### The 96 Mixing Iterations (`rsi` from `0` to `95`):

For each round $i \in [0, 95]$:
1. **Dynamic Byte Selection & S-Box Lookup:**
   $$\text{al} = (\text{edx} \oplus \text{r8d} \oplus \text{r9d} \oplus \text{ROL32}(\text{edi}, i \bmod 32)) \ \& \ \text{0xFF}$$
   $$\text{r14d} = \text{LUT}[\text{al}]$$

2. **Non-linear Register Substitution (`r8d`):**
   $$\text{shift}_1 = ((\text{r14d} \gg 27) + 1) \bmod 32$$
   $$\text{r8d} = \text{ROL32}((\text{r10d} \oplus \text{seed}) + \text{r8d} + \text{r14d}, \text{shift}_1)$$

3. **Accumulator and FNV Step:**
   $$\text{idx}_2 = ((\text{r14d} \gg 8) + \text{al} + i) \ \& \ \text{0xFF}$$
   $$\text{ecx} = (\text{edx} + \text{r11d}) + \text{r8d} + \text{LUT}[\text{idx}_2]$$
   $$\text{edx} = (\text{edx} \times \text{0x1000193}) + i$$
   $$\text{r14d} = \text{r14d} + \text{edx}$$

4. **MurmurHash3 `fmix32` Avalanche Step:**
   $$\text{fmix}(x) = (x \oplus (x \gg 16)) \times \text{0x7FEB352D} \implies \text{mix} \times \text{0x846CA68B} \implies \text{out} \oplus (\text{out} \gg 16)$$
   $$\text{edi} = \text{edi} \oplus \text{fmix}(\text{ecx})$$
   $$\text{edi} = \text{ROL32}(\text{edi}, (i \bmod 13) + 1)$$

5. **Feedback & History Array Update:**
   $$\text{edx} = \text{ROL32}(\text{edi}, (i \bmod 13) + 1) \oplus \text{r8d} + \text{r14d}$$
   $$H[i] = \text{ROL32}(\text{edi}, 11) \oplus \text{r8d} \oplus \text{edx}$$

6. **LCG Step Additions:**
   $$\text{r9d} += \text{0x045D9F3B}, \quad \text{r10d} += \text{0x27D4EB2D}, \quad \text{r11d} -= \text{0x61C88647}$$

All 96 intermediate values $H[0 \dots 95]$ are preserved in array `history` on the stack.

---

### Phase II: Verification Constraints

After completing 96 rounds, 3 independent mathematical conditions are checked:

1. **Constraint 1:**
   $$((H[7] \gg 5) \oplus (H[55] \gg 11) \oplus H[91] \oplus \text{seed}) \ \& \ \text{0xFFFF} == \text{0x9C8C}$$

2. **Constraint 2:**
   $$\text{fmix32}(H[11] \oplus H[83] \oplus \text{ROL32}(H[47], 9) \oplus \text{r8d}) == \text{0x91E50C54}$$

3. **Constraint 3:**
   $$\text{fmix32}(\text{ROL32}(H[68], 13) + H[23] + \text{edi} + \text{edx}) == \text{0xC2E4F8BD}$$

---

### Phase III: Output Flag Decryption Stream

If all 3 verification checks pass, the binary decrypts and outputs the 42-byte flag:

```c
uint32_t r14d = 7, r13d = 11, r12d = 0x5A;

for (int rbx = 0; rbx < 42; rbx++) {
    uint8_t sil = flag_enc_table[rbx] ^ ((37 * rbx) & 0xFF);

    uint32_t ecx = history[r13d % 96]; r13d += 17;
    uint32_t eax = history[r14d % 96]; r14d += 29;

    sil ^= (ecx & 0xFF);
    uint8_t dl = sil ^ ((ecx >> 8) & 0xFF);
    sil = dl ^ ((eax >> 16) & 0xFF) ^ ((eax >> 24) & 0xFF);

    uint8_t seed_byte = (seed >> (8 * (rbx % 3))) & 0xFF;
    sil ^= seed_byte;

    r12d ^= sil;
    putchar(r12d & 0xFF);
}
putchar('\n');
```

---

## 3. Solution Implementation (`solve.py`)

Because the input space is $2^{24}$ ($16,777,216$ candidates), a fast Python or C brute-force search over all seeds finishes in under 0.1 seconds.

```python
#!/usr/bin/env python3
import struct

with open('cold_start', 'rb') as f:
    data = f.read()

table_2140 = list(struct.unpack('<256I', data[0x2140:0x2140 + 256*4]))
table_2100 = list(data[0x2100:0x212a])

def rol32(x, count):
    count &= 31
    if count == 0: return x & 0xffffffff
    return ((x << count) | (x >> (32 - count))) & 0xffffffff

def fmix32(x):
    x = (x ^ (x >> 16)) & 0xffffffff
    x = (x * 0x7feb352d) & 0xffffffff
    x = (x ^ (x >> 15)) & 0xffffffff
    x = (x * 0x846ca68b) & 0xffffffff
    return (x ^ (x >> 16)) & 0xffffffff

def solve():
    for seed in range(0x1000000):
        edi = (seed * 0x9e3779b1) & 0xffffffff
        edx = ((seed << 5) ^ (seed >> 3) ^ 0x811c9dc5) & 0xffffffff
        r8d = (seed ^ 0xa3c59ac3) & 0xffffffff
        r9d = r10d = r11d = 0
        edi = rol32(edi, 7) ^ 0x1b873593

        history = [0] * 96

        for rsi in range(96):
            r15d = rol32(edi, rsi & 31)
            eax = edx ^ r8d ^ r9d ^ r15d
            al = eax & 0xff

            r14d = table_2140[al]
            shift1 = ((r14d >> 27) + 1) & 31
            tmp_a = ((r10d ^ seed) + r8d + r14d) & 0xffffffff
            eax = rol32(tmp_a, shift1)

            ecx = (edx + r11d) & 0xffffffff
            r8d = eax
            edx = (edx * 0x1000193) & 0xffffffff

            idx2 = ((r14d >> 8) + al + rsi) & 0xff
            ecx = (ecx + r8d + table_2140[idx2]) & 0xffffffff
            edx = (edx + rsi) & 0xffffffff
            r14d = (r14d + edx) & 0xffffffff

            edi = edi ^ fmix32(ecx)
            rem13 = (rsi % 13) + 1
            edi = rol32(edi, rem13)

            edx = (rol32(edi, rem13) ^ r8d + r14d) & 0xffffffff
            history[rsi] = rol32(edi, 11) ^ r8d ^ edx

            r9d = (r9d + 0x45d9f3b) & 0xffffffff
            r10d = (r10d + 0x27d4eb2d) & 0xffffffff
            r11d = (r11d - 0x61c88647) & 0xffffffff

        # Check constraints
        c1_val = (history[7] >> 5) ^ (history[55] >> 11) ^ history[91] ^ seed
        if (c1_val & 0xffff) != 0x9c8c: continue

        v1 = history[11] ^ history[83] ^ rol32(history[47], 9) ^ r8d
        if fmix32(v1) != 0x91e50c54: continue

        v2 = (rol32(history[68], 13) + history[23] + edi + edx) & 0xffffffff
        if fmix32(v2) != 0xc2e4f8bd: continue

        # Flag Generation
        r14d, r13d, r12d = 7, 11, 0x5a
        flag = []
        for rbx in range(42):
            sil = table_2100[rbx] ^ ((37 * rbx) & 0xff)
            ecx = history[r13d % 96]; r13d += 17
            eax = history[r14d % 96]; r14d += 29
            sil ^= (ecx & 0xff)
            dl = sil ^ ((ecx >> 8) & 0xff)
            sil = dl ^ ((eax >> 16) & 0xff) ^ ((eax >> 24) & 0xff)
            sil ^= (seed >> (8 * (rbx % 3))) & 0xff
            r12d = (r12d ^ sil) & 0xff
            flag.append(r12d)

        print(f"[+] Valid Seed Found: {seed:06X}")
        print(f"[+] Recovered Flag: {bytes(flag).decode('latin1')}")
        return

if __name__ == '__main__':
    solve()
```

---

## 4. Execution & Flag Verification

```bash
$ python3 solve.py
[+] Valid Seed Found: 93C7A4
[+] Recovered Flag: BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}

$ ./cold_start
========================================
               COLD START               
========================================

The system was powered down unexpectedly.

activation seed> 93C7A4
System restored.
BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}
```

## Final Flag
`BDSEC{th3_k3y_w4s_s0m3wh3r3_1n_16_m1ll10n}`
