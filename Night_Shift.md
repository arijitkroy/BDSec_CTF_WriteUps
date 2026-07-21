# Writeup: Night Shift (BDSec CTF 2026)

This document provides a highly detailed walkthrough of the steps taken to solve the **Night Shift** challenge (500 Points) by NomanProdhan.

---

## 1. Challenge Details & File Identification

* **Target File**: [night_shift.bdsec](file:///e:/ctf/night_shift.bdsec)
* **Size**: 14,592 bytes
* **Type**: 64-bit ELF (LSB pie executable)

### Core Mechanics
Upon running, the binary prints:
```
========================================
              NIGHT SHIFT
========================================
The building is closed.
Eight assignments remain.

shift code> 
```
It accepts a string of 8 integers as the "shift code" and validates them.

---

## 2. Reverse Engineering the Synchronization

Inspecting the imports and PLT stubs, the binary relies heavily on `pthread_create`, `pthread_join`, `pthread_mutex_lock`, `pthread_cond_wait`, and `pthread_cond_broadcast`.

### 1. Shared State Struct
A 328-byte shared state struct is allocated on the stack (at `rsp + 0x90` in `main`):
* `0x00`: `pthread_mutex_t` (size 40)
* `0x28`: `pthread_cond_t` (size 48)
* `0x58`: `S[0]` (32-bit state register, init: `0x13579bdf`)
* `0x5c`: `S[1]` (32-bit state register, init: `0x2468ace0`)
* `0x60`: `S[2]` (32-bit state register, init: `0x0badf00d`)
* `0x64`: `S[3]` (32-bit state register, init: `0xc001d00d`)
* `0x68`: `R[8]` (Array of 8 32-bit dwords, initialized with replicated copy of `0x2220` constant)
* `0x88`: `hash_checksum` (32-bit FNV basis, init: `0x811c9dc5`)
* `0x8c`: `inputs[8]` (8 bytes representing the parsed integers from the user)
* `0x98`: `step_index` (64-bit index counter, starts at 0)
* `0xa0`: `terminate_flag` (32-bit flag, ends thread processing when set)

### 2. Thread Coordination
The program creates 5 worker threads (indexed `0` to `4` in `bl`).
* Step `rax` (from 0 to 7) is checked sequentially.
* The thread index `bl` must match `inputs[rax]` to execute step `rax`.
* If a thread wakes up and `inputs[rax] != bl`, it goes to sleep using `pthread_cond_wait`.
* If it matches, the thread performs the state transformations for step `rax`, updates `step_index` to `rax + 1`, wakes up other threads with `pthread_cond_broadcast`, and advances to the next step.

Thus, the sequence of executing thread IDs is exactly defined by the 8 integers entered by the user!

---

## 3. Emulating the State Machine

For each step `rax` (0 to 7), the executing thread index is `bl = inputs[rax]`. The hash value `H_step` is computed on the inputs:
$$H\_step = \text{hash\_val}\Big( \big((rax + 1) \times \text{0x9e3779b9}\big) \oplus \big(bl \times \text{0x45d9f3b}\big) \Big)$$
where `hash_val` is a MurmurHash3-style 32-bit finalizer.

Depending on `bl`, a different state transformation case is executed:
* **Case 0 (`bl = 0`)**:
  * $S[0] \leftarrow \text{rol32}(S[0] \oplus H\_step,\, rax + 3)$
  * $S[2] \leftarrow (S[1] \oplus \text{0x13579bdf}) + S[2] + rax$
* **Case 1 (`bl = 1`)**:
  * $S[1] \leftarrow \text{rol32}(S[1] + S[3] + H\_step,\, 5)$
  * $S[3] \leftarrow S[3] \oplus \text{rol32}(S[0],\, 9)$
* **Case 2 (`bl = 2`)**:
  * $S[0] \leftarrow S[0] + rax + \text{0x6d2b79f5}$
  * $S[2] \leftarrow \text{rol32}(S[2] \oplus S[1] \oplus H\_step,\, 13)$
* **Case 3 (`bl = 3`)**:
  * $S[3] \leftarrow \text{hash\_val}(H\_step + S[3] + S[0])$
  * $S[1] \leftarrow (17 \times rax) \oplus S[1] \oplus \text{0xc001d00d}$
* **Case 4 (`bl = 4`)**:
  * $S[0] \leftarrow \text{rol32}(H\_step + S[3],\, 7) \oplus S[0]$
  * $S[1] \leftarrow S[1] + \text{rol32}(S[2],\, 3)$
  * $S[2] \leftarrow S[2] \oplus \text{rol32}(S[0],\, 11)$
  * $S[3] \leftarrow S[3] + rax - \text{0x5a5a5a5b}$

### Epilogue (Executed for all cases)
* $temp\_S1 = \text{rol32}(S[1],\, 5)$
* $temp\_S2 = \text{rol32}(S[2],\, 11)$
* $temp\_S3 = \text{ror32}(S[3],\, 15)$
* $epilogue\_val = temp\_S3 \oplus temp\_S2 \oplus temp\_S1 \oplus (bl \ll 24) \oplus rax \oplus S[0]$
* $R[rax] = \text{hash\_val}(epilogue\_val)$
* $term = R[rax] \oplus (bl \ll 8) \oplus hash\_checksum \oplus rax$
* $hash\_checksum \leftarrow \text{rol32}(term \times \text{0x1000193},\, 7) \oplus \text{0xa53c9e17}$

---

## 4. Constraint Solving with Z3

To solve the constraints (8 steps, 32-bit modular arithmetic and hashes), we wrote a Z3 solver script:

```python
import z3

def solve():
    s = z3.Solver()
    N = 8
    inputs = [z3.BitVec(f"in_{i}", 32) for i in range(N)]
    for i in range(N):
        s.add(inputs[i] >= 0, inputs[i] <= 4)
        
    S = [z3.BitVecVal(0x13579bdf, 32),
         z3.BitVecVal(0x2468ace0, 32),
         z3.BitVecVal(0x0badf00d, 32),
         z3.BitVecVal(0xc001d00d, 32)]
    hash_checksum = z3.BitVecVal(0x811c9dc5, 32)
    
    def hash_val_z3(val):
        val = val ^ z3.LShR(val, 16)
        val = val * 0x7feb352d
        val = val ^ z3.LShR(val, 15)
        val = val * 0x846ca68b
        val = val ^ z3.LShR(val, 16)
        return val

    def rol32(val, count):
        return (val << count) | z3.LShR(val, 32 - count)
        
    for rax in range(8):
        bl = inputs[rax]
        r15d = bl * 0x45d9f3b
        val = ((rax + 1) * 0x9e3779b9) ^ r15d
        H_step = hash_val_z3(val)
        
        S0_new = z3.BitVec(f"S0_new_{rax}", 32)
        S1_new = z3.BitVec(f"S1_new_{rax}", 32)
        S2_new = z3.BitVec(f"S2_new_{rax}", 32)
        S3_new = z3.BitVec(f"S3_new_{rax}", 32)
        
        c0_S0 = rol32(S[0] ^ H_step, rax + 3)
        c0_S2 = (S[1] ^ 0x13579bdf) + S[2] + rax
        c1_S1 = rol32(S[1] + S[3] + H_step, 5)
        c1_S3 = S[3] ^ rol32(S[0], 9)
        c2_S0 = S[0] + rax + 0x6d2b79f5
        c2_S2 = rol32(S[2] ^ S[1] ^ H_step, 13)
        c3_S3 = hash_val_z3(H_step + S[3] + S[0])
        c3_S1 = (17 * rax) ^ S[1] ^ 0xc001d00d
        c4_S0 = rol32(H_step + S[3], 7) ^ S[0]
        c4_S1 = S[1] + rol32(S[2], 3)
        c4_S2 = S[2] ^ rol32(S[0], 11)
        c4_S3 = S[3] + rax - 0x5a5a5a5b
        
        s.add(S0_new == z3.If(bl == 0, c0_S0, z3.If(bl == 2, c2_S0, z3.If(bl == 4, c4_S0, S[0]))))
        s.add(S1_new == z3.If(bl == 1, c1_S1, z3.If(bl == 3, c3_S1, z3.If(bl == 4, c4_S1, S[1]))))
        s.add(S2_new == z3.If(bl == 0, c0_S2, z3.If(bl == 2, c2_S2, z3.If(bl == 4, c4_S2, S[2]))))
        s.add(S3_new == z3.If(bl == 1, c1_S3, z3.If(bl == 3, c3_S3, z3.If(bl == 4, c4_S3, S[3]))))
                        
        temp_S1 = rol32(S1_new, 5)
        temp_S2 = rol32(S2_new, 11)
        temp_S3 = rol32(S3_new, 17)
        epilogue_val = temp_S3 ^ temp_S2 ^ temp_S1 ^ (bl << 24) ^ rax ^ S0_new
        R_rax = hash_val_z3(epilogue_val)
        
        term = R_rax ^ (bl << 8) ^ hash_checksum ^ rax
        hash_checksum_next = rol32(term * 0x1000193, 7) ^ 0xa53c9e17
        
        S = [S0_new, S1_new, S2_new, S3_new]
        hash_checksum = hash_checksum_next

    s.add(S[0] == 0x9c8a97dc)
    s.add(S[1] == 0x75a2cc72)
    s.add(S[2] == 0x1d87ef0f)
    s.add(S[3] == 0x4969e73d)
    s.add(hash_checksum == 0x4455cee8)
    
    if s.check() == z3.sat:
        m = s.model()
        vals = [m[inputs[i]].as_long() for i in range(N)]
        print(f"Solution: {vals}")
        print("Input string:")
        print(" ".join(map(str, vals)))

solve()
```

### Result
Running the solver yielded the unique SAT solution:
**`2 0 4 1 3 0 2 4`**

---

## 5. Flag Decryption

Running the ELF file inside WSL with the solved inputs:
```bash
$ ./night_shift.bdsec
========================================
========================================
              NIGHT SHIFT
========================================
The building is closed.
Eight assignments remain.

shift code> 2 0 4 1 3 0 2 4
The morning report has been approved.
BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}
```

* **Flag**: **`BDSEC{0rd3r_h1d3s_b3tw33n_th3_l1n3s}`**
