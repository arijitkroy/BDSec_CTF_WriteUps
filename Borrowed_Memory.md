# Writeup: Borrowed Memory (BDSec CTF 2026)

This document provides a highly detailed walkthrough of the steps taken to solve the **Borrowed Memory** (100 Points) challenge by NomanProdhan.

---

## 1. Challenge Details & File Identification

We started with the challenge file:
* **Target File**: [borrowed_memory.bdsec](file:///e:/ctf/borrowed_memory.bdsec)
* **Category**: Reverse Engineering
- **Points**: 100
- **Author**: NomanProdhan
- **Description**: *"Memory can be borrowed right ?"*
- **Flag Format**: `BDSEC{som3thing_her3P}`

### File Identification
Inspecting the file headers reveals:
* **Architecture**: AMD x86_64 (64-bit Linux ELF)
* **Type**: Position Independent Executable (PIE), dynamically linked, stripped.

---

## 2. Technical Analysis

Disassembly of the ELF binary (from entry point down to `main` at offset `0x10c0`) highlighted three phases:

### Phase A: PRNG Table Generation
At offset `0x111e`, a seed `0x91e10da5` is loaded. The binary loops `0x800` (2048) times to generate a PRNG lookup table and write it to `.bss` starting at address offset `0x4080`:
```python
eax = 0x91e10da5
rbx_buf = bytearray(2048)
for rdx in range(2048):
    ecx = (eax + rdx + 0x45d9f3b) & 0xffffffff
    eax = ecx
    eax = ((eax << 13) ^ eax) & 0xffffffff
    eax = ((eax >> 17) ^ eax) & 0xffffffff
    eax = ((eax << 5) ^ eax) & 0xffffffff
    ecx = (eax >> 11) & 0xffffffff
    rbx_buf[rdx] = ecx & 0xff
```

### Phase B: Self-Modifying Writes
Directly following the PRNG loop, the program runs more than 60 static RIP-relative byte, word, and dword writes modifying specific locations inside the newly generated table in `.bss` (from range `0x40c0` to `0x47c6`).

### Phase C: Input Processing Loop
The program prompts the user with:
```
0x???? -> 0x???? -> 0x????
Return what was borrowed.
```
It reads 12 pointer offsets using `fgets` and parses them using `strtoul` with base 0 (meaning inputs can be in hex format starting with `0x`).
Each offset $X[i]$ must satisfy the range check:
$$0x4000 \le X[i] \le 0x47ff$$

---

## 3. Validation Logic & Loop Emulation

The binary validates the inputs in a loop of 12 iterations starting at `0x15f0`. 

### State Propagation
In each iteration $i$, the program verifies if:
$$X[i] == si_i + 0x4000$$
where $si_i$ starts as `0x01a4` (derived from loading `[0x40a0]` $\rightarrow$ `0x7d95` and XORing it with `0x7c31`).
The next offset $si_{i+1}$ is computed depending on the key selector `cl = ((si >> 3) ^ rbx_buf[si]) & 0xff`:

1. **`cl == 0xc0` Branch**:
   Loads a 16-bit word from `si + 5`, rotates it left by `r15d` bits, and bitwise NOTs the result.
2. **`cl == 0xc1` Branch**:
   Decrypts a index-based scale factor, performs multiplication by `0x1337`, and extracts a 16-bit word from dynamic offset double-indexing.
3. **`cl == 0xc2` Branch**:
   Loads a 16-bit word from `si + 2` and XORs it with the dynamic validation state `r11d`.
4. **`cl == 0xc3` Branch**:
   Loads a little-endian word from `si + 1`, XORs it with the loop tracker `[rsp + 8]`, and adds `si`.

Additionally, the integrity of each transition is checked against a cryptographic hash equation. If any step fails, the program exits immediately.

---

## 4. Exploit & Solve Script

By statically simulating the `.bss` memory modifications and tracing the validation state transitions in Python, we can reconstruct the expected inputs:

```python
# solve.py excerpt (Reconstructed execution)
si = 0x01a4
# Loop through 12 stages...
# Next state is calculated based on rbx_buf and cl branches
# Returns the sequence: 
# 0x41a4 -> 0x42f0 -> 0x4143 -> 0x436c -> 0x421d -> 0x44a8 -> 0x40f6 -> 0x455b -> 0x4317 -> 0x468c -> 0x425a -> 0x473d
```

We also emulate the flag decryption routine located at `0x1858`, which loops 40 times over the encrypted flag bytes at `.rodata` offset `0x2220` using our solved states (`dil_buf`, `r14_buf`, and `X_buf`):
```python
flag_enc = bytes.fromhex("100d7cbb7c43685114e8eeaa7c5edc76aa77e3efdc96990d8ce7949513938f5b5e53513c245629bf")
flag = []
for rbp in range(40):
    rcx = 5 * rbp + 1
    edi = flag_enc[rbp]
    idx1 = rcx % 12
    edi ^= (29 * rbp)
    edi ^= dil_buf[idx1]
    
    idx2 = rbp % 12
    shift = (rbp % 4) * 8
    val = r14_buf[idx2]
    val_byte = (val >> shift) & 0xff
    edi ^= val_byte
    
    idx3 = (7 * rbp + 3) % 12
    edi ^= (X_buf[idx3] & 0xff)
    
    flag.append(chr(edi & 0xff))
print("FLAG:", "".join(flag))
```

Running the complete emulation outputted the flag.

---

## 5. Flag Retrieval

Feeding the computed inputs to the binary verifies the solution:

```
$ wsl ./borrowed_memory.bdsec
        _________________________________________
       /                                         \
      /          B D S e c   C T F   2 0 2 6    \
     /_____________________________________________\
     |                                             |
     |              BORROWED MEMORY                |
     |                                             |
     |       0x???? -> 0x???? -> 0x????            |
     |_____________________________________________|

Return what was borrowed.
> 0x41a4
> 0x42f0
> 0x4143
> 0x436c
> 0x421d
> 0x44a8
> 0x40f6
> 0x455b
> 0x4317
> 0x468c
> 0x425a
> 0x473d
[+] BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}
```

* **Flag**: **`BDSEC{p01nt3rs_l13_bUt_0ffs3ts_r3m3mb3r}`**
