# Writeup: Easy RE Challenge (BDSec CTF 2026)

This document provides a highly detailed walkthrough of the steps taken to solve the **Easy RE Challenge** (500 Points) by NomanProdhan.

---

## 1. Challenge Details & File Identification

We started with the challenge file:
* **Target File**: [e4sy_RE.bdsec](file:///e:/ctf/e4sy_RE.bdsec)
* **Size**: 16,768 bytes

### Inspecting File Header (Magic Bytes)
To determine the file type, we read the first 64 bytes of the binary using Python:
```python
b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00\x00\x17\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xc09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x0f\x00@\x00\x1f\x00\x1e\x00'
```
* **`\x7fELF`**: Standard ELF binary signature.
* **`\x02`**: 64-bit Architecture.
* **`\x01`**: LSB (Little Endian).
* **`\x03`**: ET_DYN (Position Independent Executable / PIE Shared Object).

---

## 2. ELF Sections & Symbol Table Analysis

Using the `pyelftools` library, we inspected the symbols and sections. 

### Key Sections:
* **`.text`**: Code segment starting at virtual address `0x10e0` (offset `0x10e0` in the file).
* **`.rodata`**: Read-only data segment starting at virtual address `0x2000` (offset `0x2000` in the file).

### Extracted Symbols:
We found several local arrays and keys defined within `.rodata`:
* **`main`**: Function starting at `0x10e0` (size: 1557 bytes).
* **`expected.0`**: Virtual address `0x23c0` (size: 24 bytes).
* **`expected.1`**: Virtual address `0x23e0` (size: 26 bytes).
* **`expected.2`**: Virtual address `0x2400` (size: 29 bytes).
* **`expected.3`**: Virtual address `0x2420` (size: 41 bytes).
* **`key_part_b.4`**: Virtual address `0x2450` (size: 8 bytes).
* **`key_part_a.5`**: Virtual address `0x2458` (size: 8 bytes).

### Dynamic Relocations (`.rela.plt`):
By mapping the relocation offsets to their PLT stub slot addresses, we identified the libc functions:
* `0x1030` $\rightarrow$ `puts`
* `0x1050` $\rightarrow$ `__stack_chk_fail`
* `0x1070` $\rightarrow$ `strcspn`
* `0x1090` $\rightarrow$ `fgets`
* `0x10b0` $\rightarrow$ `fflush`
* `0x10c0` $\rightarrow$ `fwrite`

---

## 3. Disassembly of `main`

We disassembled the code starting at `0x10e0` using `capstone` and resolved the absolute addresses of RIP-relative pointers.

### Control Flow and Input Parsing
1. The program requests input using `fgets` (`0x1090`) and strips trailing newlines using `strcspn` (`0x1070`).
2. The input length is stored in `rcx`.
3. The binary checks the length and branches as follows:
   * **If length = 41 (`0x29`)**: Jump to `0x12fb` (Case 4)
   * **If length = 29 (`0x1d`)**: Execute Case 3 (`0x11e2` to `0x12dc`)
   * **If length = 26 (`0x1a`)**: Jump to Case 2 (`0x14bc`)
   * **If length = 24 (`0x18`)**: Jump to Case 1 (`0x15d1`)
   * **Any other length**: Fails immediately ("Incorrect flag" / "That input is too long").

---

## 4. Deconstructing the Cipher Algorithms

For each case, the characters are transformed and compared against target bytes in `.rodata`. Here is the detailed step-by-step mathematical logic for each branch:

### Case 1: Length 24 (`expected.0` at `0x23c0`)
* **Core Loop**:
  Iterates $i$ from 0 to 23.
  $$C[i] = \text{rol8}\Big(eax_{prev} + (P[i] \oplus ecx),\, 3\Big)$$
  * $ecx$ starts at `0x55` and increases by `0x11` per iteration.
  * $eax$ starts at `0x6b` and tracks the previous cipher byte.
* **Reversal Logic**:
  $$eax_{curr} = \text{ror8}(C[i],\, 3)$$
  $$P[i] = (eax_{curr} - eax_{prev}) \oplus ecx$$

### Case 2: Length 26 (`expected.1` at `0x23e0`)
* **Core Loop**:
  Iterates $rsi$ from 0 to 25.
  $$C[\text{idx}] = \text{ror8}\Big(P[rsi] \oplus r9,\, (rsi \pmod 5) + 1\Big)$$
  * $\text{idx} = (rsi \times 5) \pmod{26}$ (which permutes indices 0-25).
  * $r9$ starts at `0x3d` and increases by `7` per iteration.
* **Reversal Logic**:
  $$P[rsi] = \text{rol8}\big(C[\text{idx}],\, (rsi \pmod 5) + 1\big) \oplus r9$$

### Case 3: Length 29 (`expected.2` at `0x2400`)
* **Core Loop**:
  Iterates $i$ from 0 to 28.
  For optimization, the first 16 bytes are vectorized using SIMD, and the remaining 13 bytes use a scalar loop. Both sections map to the same mathematical formula:
  $$C[i] = \text{rol8}\Big(P[i] + (0x21 + 3 \times i),\, 2\Big) \oplus 0xa7$$
* **Reversal Logic**:
  $$P[i] = \text{ror8}\big(C[i] \oplus 0xa7,\, 2\big) - (0x21 + 3 \times i)$$

### Case 4: Length 41 (`expected.3` at `0x2420`)
* **Core Loop**:
  Iterates $i$ from 0 to 40.
  $$C[\text{idx}] = \Big(\text{rol8}\big(P[i] \oplus k,\, (i \pmod 7) + 1\big) + \big((11 \times i) \oplus 0x23\big)\Big) \pmod{256}$$
  * $\text{idx} = (13 \times i) \pmod{41}$ (coprime permutation).
  * $k = \text{key\_part\_a}[i \pmod 8] \oplus \text{key\_part\_b}[i \pmod 8]$.
* **Reversal Logic**:
  $$val\_rot = \Big(C[\text{idx}] - \big((11 \times i) \oplus 0x23\big)\Big) \pmod{256}$$
  $$val\_xor = \text{ror8}\big(val\_rot,\, (i \pmod 7) + 1\big)$$
  $$P[i] = val\_xor \oplus k$$

---

## 5. Python Solver Script

The following Python script was executed to extract the flags:

```python
def rol8(val, count):
    return ((val << count) | (val >> (8 - count))) & 0xFF

def ror8(val, count):
    return ((val >> count) | (val << (8 - count))) & 0xFF

# Extracted constants from .rodata
expected_0 = [12, 97, 228, 109, 90, 89, 216, 166, 114, 25, 149, 173, 8, 36, 90, 43, 227, 96, 26, 46, 199, 138, 224, 12]
expected_1 = [191, 227, 39, 118, 69, 128, 124, 248, 20, 171, 224, 202, 78, 111, 48, 49, 141, 183, 199, 122, 240, 200, 211, 252, 248, 141]
expected_2 = [46, 14, 106, 10, 118, 9, 33, 58, 213, 26, 221, 125, 121, 33, 13, 101, 61, 132, 125, 132, 145, 89, 232, 253, 205, 204, 168, 48, 108]
expected_3 = [35, 5, 121, 27, 108, 193, 132, 15, 136, 178, 125, 235, 160, 126, 244, 50, 198, 245, 112, 193, 197, 38, 191, 22, 221, 66, 54, 58, 106, 106, 69, 23, 244, 76, 205, 132, 174, 39, 140, 200, 56]

key_part_b = [91, 117, 180, 123, 203, 93, 115, 230]
key_part_a = [25, 164, 199, 82, 110, 1, 155, 240]

# --- Solving Case 1 (Length 24) ---
p0 = []
eax = 0x6b
ecx = 0x55
for i in range(24):
    c_val = expected_0[i]
    eax_curr = ror8(c_val, 3)
    p_val = ((eax_curr - eax) & 0xFF) ^ ecx
    p0.append(p_val)
    eax = eax_curr
    ecx = (ecx + 0x11) & 0xFF

# --- Solving Case 2 (Length 26) ---
p1 = [0] * 26
r9 = 0x3d
for rsi in range(26):
    idx = (rsi * 5) % 26
    c_val = expected_1[idx]
    rot_amt = (rsi % 5) + 1
    val_xor = rol8(c_val, rot_amt)
    p1[rsi] = val_xor ^ r9
    r9 = (r9 + 7) & 0xFF

# --- Solving Case 3 (Length 29) ---
p2 = []
for i in range(29):
    c_val = expected_2[i]
    val_rot = c_val ^ 0xa7
    val_add = ror8(val_rot, 2)
    p2.append((val_add - (0x21 + 3 * i)) & 0xFF)

# --- Solving Case 4 (Length 41) ---
p3 = [0] * 41
for i in range(41):
    idx = (13 * i) % 41
    c_val = expected_3[idx]
    val_rot = (c_val - ((11 * i) ^ 0x23)) & 0xFF
    val_xor = ror8(val_rot, (i % 7) + 1)
    k = key_part_a[i % 8] ^ key_part_b[i % 8]
    p3[i] = val_xor ^ k

print("Flag 24 (raw):", p0)
print("Flag 26:", bytes(p1).decode('ascii'))
print("Flag 29:", bytes(p2).decode('ascii'))
print("Flag 41:", bytes(p3).decode('ascii'))
```

---

## 6. Discovered Flags

Executing the script produced the following results:
* **Flag 24**: `[67, 205, 7, 153, 7, 74, ...]` (Junk / Non-printable)
* **Flag 26**: `BFLAG{r3v3rS1ng_1s_4n_4rT}`
* **Flag 29**: `AFLAG{n1c3_trY_bUt_n0_p01nTs}`
* **Flag 41 (Final Submission Flag)**: **`BDSEC{e4SY_r3v3rS3_eNg1N33r1nG_cH4LL4ng3}`**
