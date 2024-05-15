---
layout: post
title: "Hackon User Manager - Writeup | HackOn 2023 (Mobile Challenge)"
author: Jorge Moreno
category: Easy
---

## Challenge Description

---

> hackon-user-manager.apk
> 

Category: **Mobile**  
Difficulty: **Very Easy**

## Challenge Solution

---

First of all we are going to open the apk in an Android emulator. I will use Bluestacks so I can save time in installing a different one in the Kali machine.

In the app we can see 3 tabs: 

- **Prizes**: Shows the prizes of the CTF event
- **Rules**: Shows the rules of the CTF event
- **Admin zone**: a login panel.

I will use ``apktool`` to reverse engineer the apk.

```console
sudo apt install apktool
apktool d hackon-user-manager.apk
```

This will convert the apk into a bunch of files, including code in Javascript. Doing a quick research we find the following file: ``assets/public/420.138bfe4728829c81.js`` inside of which we find this interesting functions:

```jsx
[...]
rotatatatatatatatatatatatatate(a) {
		a.replace(/[a-z]/gi, u => "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM" \
		["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".indexOf(u)])
}
[...]
```

This function rotates the alphabet 13 positions (decodes ROT13 Cypher).

And the function ``check()``

```jsx
[...]
check() {
        "admin" === this.user && this.password === this.rotatatatatatatatatatatatatate("Unpxba2023!@$") ? \ 
		this.presentAlert("SIUU", "Felicidades crack", this.zpqwug()) : \
		this.presentAlert("NOPE", "Sigue probando suerte", "Solo el admin puede acceder a esta funcionalidad")
}
[...]
```

Which checks if the password for the admin user is the string ``"Unpxba2023!@$"`` decoded from ROT13, if it is correct it prints something called ``this.zpqwug()`` (flag?) along with a message, and if it isn’t prints an error message. 

The password we get after decoding is ``Hackon2023!@$.``, Now we can send the credentials we got from here into the app and see what happens.

![Untitled](images/Hackon-user-manager/Untitled.png)


**FLAG -- HackOn{4ndr01d_4pp_1s_4_w3bp4g3}**