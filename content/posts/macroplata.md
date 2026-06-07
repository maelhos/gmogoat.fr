---
date: '2026-04-12T12:37:52+02:00'
title: 'Macroplata - FCSC 2026'
math: true
tags:
    - CTF
    - FCSC2026
    - Crypto
---

## Introduction

**Macroplata** : Just WHY man ? was my first reaction to this challenge... I usually don't really like challenges with a lot of code `:-)`
Soooo, basically there are 3 KEMS and some sort of TAG/authentification thing, my first instinct was : I'm NOT looking into the details of the KEMs before I have something on the actual thing that we're supposed to to which is: **forging a tag**.

All that we need to do is an existencial forgery from a tag with known plaintext...

{{< figure src="/images/lattice.jpeg" >}}

## The tagging

The tagging mecanism is basically a recursive AES enc with a few twists depending on the ... block padding ?
I hope ANSSI didn't mean to change KEM depending on the padding when they recommened hybrid solutions `:-)`

Well let's consider a seqences of 16 bytes blocks (meaning all of them are 16 bytes so don't need padding), $b_1, \cdots, b_n$, then the tag is of the form:

$$T(b_1, \cdots, b_n) = E_{K_0}\left(E_{K_0}\left(\cdots E_{K_0}\left(E_{K_0}\left(b_1\right) \oplus b_2\right) \cdots\right) \oplus b_n \oplus K_1\right)$$

And particular the known tag is exactly $32$-bytes so is of the form:

$T_0 = T(k_1, k_2 ) = E_{K_0} \left( E_{K_0} \left( k_1\right) \oplus k_2 \oplus K_1\right)$

Where $E_{K_0}$ is AES-ECB with key $K_0$ and $K_1$ is the key to the lattice KEM. Note that to win we can forge a tag of ANY length...

## The KEMs

Well since the key to the AES seem to be the most important let's look at the EC-KEM that derives it... Well its called `ECElGamalKEM` but it looks more like `ECDH` and ... seems pretty secure. No luck here...

I didn't really want to look at the lattice KEM too fast as it's a LOT of code (Maybe I should have in retrospective hum hum...), so I thought that maybe I should look at the RSA KEM. The RSA KEM was SO simples that I was also convinced it had no real vulnerability.

BUT I SILL didn't want to look at the lattice KEM until I actually find a forgery that requires only $K_1$ so I did that.

## The forgery

We don't know a lot... we know $k_1, k_2, T_0$ and possibly $K_1$ soooo what can we do.
Well if we don't want to involve $K_2$ we need full size blocks. So here I proceeded iterativly:

- Can I forge a TAG for one block ?

$T(b_1) = E_{K_0}(b_1 \oplus K_1)$, since I only know one encryption with $K_0$ then necessarly I need that $b_1 \oplus K_1 = E_{K_0} \left( k_1\right) \oplus b_2 \oplus K_1$ which is equivalent to $b_1 \oplus b_2 = E_{K_0} \left( k_1\right)$, unfortunatly, there is NO WAY I get my hands on $E_{K_0} \left( k_1\right)$...

- Can I forge a TAG for two blocks ?

Well I didn't really try, since I assumed it would basically be the same as the given tag, maybe I'm wrong ?

- Can I forge a TAG for three blocks ?

Same process : $T(b_1, b_2, b_3) = E_{K_0} \left( E_{K_0} \left( E_{K_0} \left( b_1\right) \oplus b_2\right)  \oplus b_3 \oplus K_1\right)$ ... I didn't succeed but I felt like with a little more degree of freedom I could do it...

- Can I forge a TAG for four blocks ?

$T(b_1, b_2, b_3, b_4) = E_{K_0}( E_{K_0}( E_{K_0}( E_{K_0}( b_1) \oplus b_2) \oplus b_3)  \oplus b_4 \oplus K_1)$

As before, I'm forced to take $b_4 = k_2$ and $E_{K_0}( E_{K_0}( b_1) \oplus b_2) \oplus b_3 = b_1$ since it's the only way that I can match the given tag, I get:

$$T_0 = T(E_{K_0}( E_{K_0}( b_1) \oplus b_2) \oplus b_3, b_2, b_3, k_2)$$

and applying the same logic, I'm forced to take: $b_1 \oplus b_3 = T_0$ and $b_2 = k_2 \oplus K_1$ which gives:

$$T_0 = T(E_{K_0}( E_{K_0}( b_1) \oplus k_2 \oplus K_1) \oplus b_1 \oplus T_0 , k_2 \oplus K_1, b_1 \oplus T_0, k_2)$$

and clearly, now we want $b_1 = k_1$ which simplifies evrything to:

$$T_0 = T(k_1, k_2 \oplus K_1, b_1 \oplus T_0, k_2)$$

## Just find $K_1$

Well, let's just say I just printed $v$ from the lattice KEM, was met with:

```
[27967643, 27967643, 27967643, 27967643, 11189146, 11189146, 27967643, 11189146, 27967643, 11189146, 27967643, 27967643, 11189146, 11189146, 11189146, 11189146, 11189146, 27967643, ...]Z
```

Note that for this part I was SOOO lazy in my solve that i randomly pick one of the values to be $0$ and the other to be $1$ so the final solve works half the time.

{{< figure src="/images/no-sully.gif" >}}


Sooo yeah, it's pretty obvious this is beyond broken...

## Putting it all together

Here is the final solve:

```python
from pwn import remote, process
from Crypto.Util.number import *
import pickle
from Crypto.Hash import SHAKE256, SHA256
import base64
import numpy as np
from Crypto.Protocol.KDF import HKDF
#io = process(["python", "macroplata.py"])
io = remote("challenges.fcsc.fr", 2158)

pk = pickle.loads(base64.b64decode(io.recvline().strip().decode()))
ct = base64.b64decode(io.recvline().strip().decode())
truth = io.recvline().strip()
tag = base64.b64decode(io.recvline().strip().decode())

l1 = int.from_bytes(ct[:4])
ct_ec = ct[4:4+l1]

l2 = int.from_bytes(ct[4+l1:8+l1])
ct_lat = ct[8+l1:8+l1+l2]

l3 = int.from_bytes(ct[8+l1+l2:12+l1+l2])
ct_rsa = ct[12+l1+l2:12+l1+l2+l3]

n = 512
q = 33556993
B = 2

seed, t = pk[1]
A = np.array([
            [int.from_bytes(SHAKE256.new(data=seed+i.to_bytes(2,'big')+j.to_bytes(2,'big')).read(2), 'big') % q for j in range(n)]
            for i in range(n)
        ])

u, v = pickle.loads(ct_lat)
v = list(v)

m = [el == v[0] for el in v]
z = b""

for i in range(0, len(m), 8):
    v = 0
    ii = i
    for j in range(7, -1, -1):
        v |= 2**j * m[ii]
        ii += 1
    z += bytes([v])
K1 = HKDF(z, 16, b"", SHA256)

b1, b2 = truth[:16], truth[16:]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

forged = b1 + xor(b2, K1) + xor(tag, b1) + b2

print(io.recvuntil(b":"))
io.sendline(base64.b64encode(forged))
io.sendline(base64.b64encode(tag))

print(io.recvline())
```