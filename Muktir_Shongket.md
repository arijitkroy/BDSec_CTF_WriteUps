# Writeup: Muktir Shongket (BDSec CTF 2026)

This document provides a detailed walkthrough of the steps taken to solve the **Muktir Shongket** challenge (360 Points) by NomanProdhan.

---

## 1. Challenge Details & Scouting

* **Connection Info**: `nc 45.56.67.129 53916`
* **Binary File**: `muktir_shongket` (64-bit ELF executable)
* **Category**: PWN & Jail
* **Difficulty**: Intermediate

### Target Environment
Connecting to the netcat service exposes a console menu:
```
========================================
             MUKTIR SHONGKET
       FIELD COMMUNICATION TERMINAL
========================================
Every transmission requires command approval.

1. Upload coded transmission
2. Inspect decoded orders
3. Verify transmission
4. Execute transmission
5. Clear terminal
6. Disconnect
> 
```

---

## 2. Reverse Engineering

Disassembling the binary `muktir_shongket` reveals the following structure:
* **Option 1 (Upload)**: Reads a hex-encoded string of up to `0x480` characters, validates and decodes the hexadecimal payload into a global buffer at `0x404080`.
* **Option 2 (Inspect)**: Parses the decoded bytecode in the buffer and prints a disassembly representation of it.
* **Option 3 (Verify)**: Simulates route checking to approve the transmission.
  - The verification parser validates a subset of custom opcodes:
    - `0x10`: `WAIT`
    - `0x20`: `SIGNAL`
    - `0x30`: `ROUTE` followed by a 1-byte relative jump size.
    - `0x40`: `END`
    - `0xf0`: `FREEDOM`
  - It expects the route to start at offset `0` and jump forwards/backwards safely without landing outside bounds, eventually terminating precisely at an `0x40` (`END`) order.
* **Option 4 (Execute)**: Translates the custom bytecode into machine code, writes it to a dynamically allocated memory area via `mmap`, marks it executable using `mprotect`, and executes it.
* **Hidden Flag Function**:
  - A function at `0x401bb0` opens `"flag.txt"`, reads the flag, and outputs it to stdout under the banner: `[+] Freedom broadcast authenticated.`.

---

## 3. Vulnerability Analysis & Exploitation

### Translation & Route Discrepancy
The core vulnerability lies in the mismatch between how the verification routing engine parses jumps and how the translation engine compiles them into executable x86-64 shellcode:

1. **Verification Logic (`ROUTE` / `0x30`)**:
   - The parser reads `0x30` followed by a jump target byte value. It validates that the jump destination index points to a valid offset.
   - However, during the compilation phase, when the translator sees `0x30`, it encodes a short relative jump (`0xeb`) or a near relative jump (`0xe9`) using the subsequent byte directly as the raw relative target displacement.
   
2. **Abusing `SIGNAL` (`0x20`) and inline assembly shellcode**:
   - The translator handles the `SIGNAL` (`0x20`) instruction by encoding a 9-byte pattern.
   - However, during verification, the router parser checks the `SIGNAL` (`0x20`) byte, skipping 9 bytes, but it does **not** inspect the content of those 9 bytes.
   - This allows us to hide arbitrary x86-64 machine code bytes inside the arguments of `SIGNAL` (`0x20`), effectively shielding arbitrary instructions from the verification parser.

### Exploit Payload Design
We craft a bytecode sequence that:
1. Performs a `ROUTE` jump (`0x30`) past the verification boundary.
2. Embeds a `SIGNAL` (`0x20`) command to mask our payload.
3. Hides the x86-64 assembly instructions to jump to the flag printing function (`0x401bb0`) inside the mask.
4. Appends `0x40` (`END`) to satisfy the verification parser's requirement.

**Bytecode breakdown**:
* `30 02`: `ROUTE` with offset 2 (jumps past `30 02` directly to the `SIGNAL` payload).
* `20`: `SIGNAL` opcode.
* `b8 b0 1b 40 00`: x86-64 assembly `mov eax, 0x401bb0` (address of flag printer).
* `ff e0`: x86-64 assembly `jmp rax` (jumps to the flag printer).
* `90`: `nop` alignment byte.
* `40`: `END` opcode (validates end boundary).

Raw hex payload:
```
300220b8b01b4000ffe09040
```

---

## 4. Execution & Flag Retrieval

Running the exploit script to upload, verify, and execute the payload yields the flag:

```bash
$ python exploit_muktir.py
Uploading payload...
Hex transmission: Stored 12 transmission bytes.

Verifying payload...
Transmission approved by command verification.

Executing payload...
Execution Output:
Relaying orders to field execution engine...

[+] Freedom broadcast authenticated.
BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}
Transmission execution completed.
```

* **Flag**: **`BDSEC{mukt1r_5h0ngk3t_r34ch3d_th3_f13ld}`**
