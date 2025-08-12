---
date: '2025-08-12T19:48:50+02:00'
title: 'Jafar - FCSC 2025'
math: true
tags:
    - CTF
    - FCSC2025
    - Crypto
---

## Overview

Jafar is a SPN with 2 main aspect a round function $R$ and a middle part $M$.
The Jafar Encryption can be simply decribed as $J = R \circ M \circ R$, where $M$ is the middle part and $R$ correspond to the 20 rounds of *AddKey*, *Sbox* and *Permute*.
Since we are given only a limited amount of queries and that we have access to both encryption and decryption, **boomerang attack** comes to mind pretty quickly but in boomeran we need 2 encryptions and 2 decryptions...

{{< figure src="/images/meme_jafar.jpg" >}}

## Analysis

The first thing to do when we have a SBox is to steal Poustouflan's tool and run it...

```text
SBox is not linear.
However, these equations hold with probability 100.0%:
  y7 = x4 
  y2 = x6 
  y7 ⊕ y2 = x6 ⊕ x4 
where y = S(x).
This can be considered as a cryptographic weakness and can lead to linear cryptanalysis.

SBox is differential! For all x,
  S(x)⊕129 = S(x⊕24)
  S(x)⊕7 = S(x⊕74)
  S(x)⊕134 = S(x⊕82)
```

Since we only have 3 queries, linear attack is unlickly (3 bits of linear is not enough).
So let's look into the differential attack.

## Differential for the round function

When we have a differential for the SBox, it's pretty common to just try to get a differential for the whole round.

A very lazy but fast way to do this without fancy MILP is realise that our differential for each byte is either 0, 24, 74 or 82. So since we have 16 bytes thats $4^{16} = 2^{32}$ possibilities. Let's BF...

We can cut any differential path that end up having a non differential as the input of one of the SBox

```python
delta = {0: 0, 24: 129, 74: 7, 82: 134}

pos = list(delta.keys())

for diff in product(pos, repeat=16):
    state = list(diff)
    good = True
    for rnd in range(20):
        for i in range(16):
            if not state[i] in pos: 
                good = False
                break
            else:
                state[i] = delta[state[i]]
        if not good: break
        state = Permute(state)
    if not good: continue

    print("GOOD :", diff, "|", state)
```

Eventually we find the differential pair:

```python
full_diff_in  = (0, 0, 0, 0, 0, 74, 0, 0, 0, 0, 24, 0, 0, 74, 0, 0)
full_diff_out = (0, 0, 74, 0, 0, 0, 0, 0, 82, 0, 0, 24, 0, 0, 0, 0)
```

## Full Cipher

What we are going to do is then very similar to boomerang, our goal will be to deduce a pair cleartext/ciphertext $P, C$ without asking for it.

Let's recall some of the properties so far:

- $\forall P: R(P + \Delta) = R(P) + \Delta'$
- $\forall P: R^{-1}(P + \Delta') = R^{-1}(P) + \Delta$
- $\forall P, Q: M(P + Q) = M(P) + M(Q)$ as $M$ is just a multiplication in a Galois field so it's linear
- $\forall P, Q: M^{-1}(P + Q) = M^{-1}(P) + M^{-1}(Q)$ and so is it's inverse

Let's now consider a fixed plaintext $p$ that we know, the only two first reasonable queries we might do is either $J(p + \Delta)$ or $J^{-1}(p + \Delta')$, let's start with the first (I think both work by symmetry...):

$$ C_1 = J(p + \Delta) = R(M(R(p + \Delta))) = R(M(R(p) + \Delta'))$$

From there again, logically the only thing we can do here is decrypt... Decrypting the same thing really doest make sense so let's do the only sensible thing :

$C_2 = J^{-1}(C_1 + \Delta') = R^{-1}(M^{-1}(R^{-1}(C_1 + \Delta'))) = R^{-1}(M^{-1}(R^{-1}(C_1) + \Delta)) = R^{-1}(M^{-1}(R^{-1}(C_1)) + M^{-1}(\Delta))$

and :

$C_2 = R^{-1}(M^{-1}(R^{-1}(C_1 +\Delta'))) = R^{-1}(M^{-1}(R^{-1}(C_1) +\Delta)) = R^{-1}(M^{-1}(M(R(p) + \Delta') +\Delta))$

and.....

$$ C_2 = R^{-1}(R(p) + \Delta' + M^{-1}(\Delta))$$

You get the idea, by elimination we should probably do $J(C_2 + \Delta)$

$ C_3 = J(C_2 + \Delta) = R(M(R(C_2 + \Delta))) = R(M(R(C_2) + \Delta')) = R(M(R(p) + \Delta' + M^{-1}(\Delta) + \Delta')) = R(M(R(p) + M^{-1}(\Delta)))$

And good grief finally :

$$ C_3 = R(M(R(p)) + \Delta) = R(M(R(p))) + \Delta' = J(p) + \Delta'$$

And boom here it is then $(p, C_3 + \Delta')$ is a valid plaintext/ciphertext that's not been queried before...

## Wrap-up and code

Very fun challenge, knowning about boomerang really helped, the proof is longer than it needs to be but very pleasing.

```python
from pwn import remote, process
from Crypto.Util.number import *
from sage.all import *
from itertools import product
import os
from chall import *


def xor(a, b):
    return bytes(k ^ l for k, l in zip(a, b))


delta = {0: 0, 24: 129, 74: 7, 82: 134}

pos = list(delta.keys())

for diff in product(pos, repeat=16):
    state = list(diff)
    good = True
    for rnd in range(20):
        for i in range(16):
            if not state[i] in pos: 
                good = False
                if rnd > 1: print(rnd)
                break
            else:
                state[i] = delta[state[i]]
        if not good: break
        state = Permute(state)
    if not good: continue

    print("GOOD :", diff, "|", state)

#io = process(["python", "chall.py"])
io = remote("chall.fcsc.fr", 2153)
full_diff_in  = (0, 0, 0, 0, 0, 74, 0, 0, 0, 0, 24, 0, 0, 74, 0, 0)
full_diff_out = (0, 0, 74, 0, 0, 0, 0, 0, 82, 0, 0, 24, 0, 0, 0, 0)

P = os.urandom(16)

####
io.recvuntil(b">>> ")
io.sendline(b"enc")
io.recvuntil(b">>> ")
io.sendline(xor(P, full_diff_in).hex().encode())
io.recvline()

C = bytes.fromhex(io.recvline().decode().strip())

####
io.recvuntil(b">>> ")
io.sendline(b"dec")
io.recvuntil(b">>> ")
io.sendline(xor(C, full_diff_out).hex().encode())
io.recvline()

A = bytes.fromhex(io.recvline().decode().strip())

####
io.recvuntil(b">>> ")
io.sendline(b"enc")
io.recvuntil(b">>> ")
io.sendline(xor(A, full_diff_in).hex().encode())
io.recvline()

B = bytes.fromhex(io.recvline().decode().strip())

###############
io.recvuntil(b">>> ")
io.sendline(P.hex().encode())

io.recvuntil(b">>> ")
io.sendline(xor(B, full_diff_out).hex().encode())

print(io.recvline())
print(io.recvline())
```
