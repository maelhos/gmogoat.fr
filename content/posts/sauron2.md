---
date: '2025-08-12T19:48:50+02:00'
title: 'La revanche de Sauron - FCSC 2024'
math: true
tags:
    - CTF
    - FCSC2024
    - Crypto
---

## At quick glance

In this challenge we have a pretty single encryption scheme and very few relations to work with, smells like lattice to me...

{{< figure src="/images/lll_go_brrrrr.gif" >}}

## Analysis

There are only two blocks so let's put it into a system:

$$b_1 \texttt{iv}_1 + k_1 s = c_1$$
$$b_2 \texttt{iv}_2 + k_2 s = c_2$$

Here lattice will surely work because of the imbalance in term of coefficient sizes :

- $b_1, b_2$ are 256 bits
- $s$ is 1024 bits
- $\texttt{iv}_1, \texttt{iv}_2$ are 1024 as well
- $k_1, k_2$ are 1024 bits

So the blocks are way smaller, let's build a null combinaison and encourage LLL/BKZ to go towards it with scalling:

$$k_2 b_1 \texttt{iv}_1 + k_1 k_2 s = k_2 c_1$$
$$k_1 b_2 \texttt{iv}_2 + k_1 k_2 s = k_1 c_2$$

So

$$k_2 b_1 \texttt{iv}_1 - k_1 b_2 \texttt{iv}_2 - k_2 c_1 + k_1 c_2 = 0$$

The reason we want to eliminate $s$ is is because we want linear combinaisons of the unknowns and $k_1 s$ or $k_2 s$ prevent that.

## ~~LLL~~ BKZ time

So from the equation above the coefficients we want in front of $c_1$ and $c_2$ should be 256 bits smaller than the ones in from of $\texttt{iv}_1$ and $\texttt{iv}_2$, so with the right scalling (scalling heavily on the null equation ofc) we can use the lattice :

$$
\begin{bmatrix}
    2^{1024}c_1 & 2^{1024}c_2 & 2^{1024}\texttt{iv}_1 & 2^{1024}\texttt{iv}_2 \\
    2^{256} & 0 & 0 & 0 \\
    0 & 2^{256} & 0 & 0 \\
    0 & 0 & 1 & 0 \\
    0 & 0 & 0 & 1
\end{bmatrix}
$$

## The code

That is pretty much it (we also have to deal with the sign but that's no big deal)

```python
from pwn import remote, process
from Crypto.Util.number import *
from sage.all import *
from gmo.all import *
import json

f = json.loads(open("out.txt", "r").read())
bs = 1024 // 32

iv1 = f[0]["iv"]
c1 = f[0]["c"]

iv2 = f[1]["iv"]
c2 = f[1]["c"]

lattice = [[c1, c2, iv1, iv2],
           [1,  0,  0,   0],
           [0,  1,  0,   0],
           [0,  0,  1,   0],
           [0,  0,  0,   1]]


lat = matrix(ZZ, lattice).transpose()
scale = diagonal_matrix([2**1024, 2**256, 2**256, 1, 1])

r = (lat * scale).BKZ() / scale
flag = b""
for v in r:
    if v[0] == 0:
        print(v)
        k2, k1, k2b1, k1b2 = list(map(int, v[1:]))
        if k2b1 % k2 == 0 and k1b2 % k1 == 0:
            b2 = k1b2 // k1
            b1 = k2b1 // k2
            if b1 < 0:
                b1 *= -1
                b2 *= -1
            print(int.to_bytes(b1, bs,"big") + int.to_bytes(b2, bs,"big"))

```

And the flag: `FCSC{8fd540e4620d3b873be4dcc074e3fb84f528a5800ffbb31dd158a8b7d5}`
