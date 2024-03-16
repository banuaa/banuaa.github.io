---
layout: post
title:  "UIUCTF 2023 - Group Project [Cryptography]"
date:   2023-10-09 00:00:00
description: "UIUCTF 2023 - Group Project [Cryptography] Writeup"
tag:
  - Cryptography
---

Last week, i participated in UIUCTF 2023 with the TCP1P team and managed to solve several challenges. One of the challenges that I solved was the Group Project (Cryptography).

**Challenge Description:**\
`In any good project, you split the work into smaller tasks…`\
`nc group.chal.uiuc.tf 1337`

**Attachment (chal.py):**

``` python
from Crypto.Util.number import getPrime, long_to_bytes
from random import randint
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


with open("/flag", "rb") as f:
    flag = f.read().strip()

def main():
    print("[$] Did no one ever tell you to mind your own business??")

    g, p = 2, getPrime(1024)
    a = randint(2, p - 1)
    A = pow(g, a, p)
    print("[$] Public:")
    print(f"[$]     {g = }")
    print(f"[$]     {p = }")
    print(f"[$]     {A = }")

    try:
        k = int(input("[$] Choose k = "))
    except:
        print("[$] I said a number...")

    if k == 1 or k == p - 1 or k == (p - 1) // 2:
        print("[$] I'm not that dumb...")

    Ak = pow(A, k, p)
    b = randint(2, p - 1)
    B = pow(g, b, p)
    Bk = pow(B, k, p)
    S = pow(Bk, a, p)

    key = hashlib.md5(long_to_bytes(S)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    c = int.from_bytes(cipher.encrypt(pad(flag, 16)), "big")

    print("[$] Ciphertext using shared 'secret' ;)")
    print(f"[$]     {c = }")


if __name__ == "__main__":
    main()
```

**Analysis:**

``` python
    .....snip....
    key = hashlib.md5(long_to_bytes(S)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    c = int.from_bytes(cipher.encrypt(pad(flag, 16)), "big")

    print("[$] Ciphertext using shared 'secret' ;)")
    print(f"[$]     {c = }")
    ....snip....
```

It is known that the key is the MD5 hash of the **“S”**, which is then returned in a byte format. This key is used to encrypt the flag using AES ECB mode.

To decrypt the AES ECB mode, this key is required.

**How to get the Key?**\
As we can see in the source code above, the script require user input for the value of **“k”**. There is if condition specifically checking for the weak values of **“1”**, **“p-1”**, and **“(p-1) // 2”**. So, we cannot use that values as the input for **“k”**.

Because its only checking for the specific weak values, i used the sympy.totient python library to count the positive integers less than **“p”** and coprime with **“p”**. It does not necessarily yield the same values as **“1”, “p-1”, or “(p-1) // 2”**.

When we choose the **“k”** to be the totient of **“p”**, a fascinating property arises. The property is that for any positive integer **“a”** and prime number **“p”**, **“a ^ phi(p) = 1 (mod p)”** holds if **“a”** is coprime with **“p”**.

``` python
    ....snip....
    try:
        k = int(input("[$] Choose k = "))
    except:
        print("[$] I said a number...")

    if k == 1 or k == p - 1 or k == (p - 1) // 2:
        print("[$] I'm not that dumb...")

    Ak = pow(A, k, p)
    b = randint(2, p - 1)
    B = pow(g, b, p)
    Bk = pow(B, k, p)
    S = pow(Bk, a, p)
    ....snip...
```

In the given code, after computing **Ak = pow(A, k, p)**, **“Ak”** will become **1 (mod p)** due to the property mentioned above. Consequently, when **“Bk”** is computed as **pow(B, k, p)**, it will also be equal to **1 (mod p)**. As a result, when computing **S = pow(Bk, a, p)**, **“S”** will still be **1 (mod p)** since **1** raised to any power is still **1**.

Since the shared secret **“S”** is always equal to **1 (mod p)** when **“k”** is the totient of **“p”**, the derived encryption key **“key”** will be the **MD5** hash of the same value every time. This results in a **predictable encryption key**.

**Solver:**

``` python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from sympy import *
from pwn import *
import hashlib

io = remote("group.chal.uiuc.tf", 1337)
io.recvuntil(b"business??\n[$] Public:\n")
g = io.recvline().decode("utf-8").replace("[$]     ", "").replace("\n", "")
p = io.recvline().decode("utf-8").replace("[$]     ", "").replace("\n", "")
A = io.recvline().decode("utf-8").replace("[$]     ", "").replace("\n", "")

# if k == 1 or k == p - 1 or k == (p - 1) // 2:
k = totient(p.split("p = ")[1])

io.sendline(str(k).encode())
io.recvuntil(b"Ciphertext using shared 'secret' ;)\n")

c = io.recvline().decode("utf-8").replace("[$]     ", "").replace("\n", "")

io.close()

g = int(g.split("g = ")[1])
p = int(p.split("p = ")[1])
A = int(A.split("A = ")[1])
c = int(c.split("c = ")[1])

S = pow(A, k, p)

print(f"[+] K = {k}")
print(f"[+] S = {S}")

key = hashlib.md5(long_to_bytes(S)).digest()
print(f"[+] Key = {key}")
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(long_to_bytes(c)).decode("utf-8")
print(f"[+] Flag = {flag}")
```

We got the flag!

![Flag](images/UIUCTF2023_flag.png)

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn