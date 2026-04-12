---
date: '2026-04-12T12:37:47+02:00'
draft: true
title: 'Splhash'
tags:
    - CTF
    - FCSC2026
    - Crypto
---


# Writeup splhash - GMO_Goat - FCSC2026

## Introduction

**Splhash** is a hash function presented as $H(x) = B \times S(A \times x)$ where $A$ is a $2n \times 5n$ matrix and $B$ is a $5n \times n$ matrix.
The non-linear $S$-layer is comprised of $\cfrac{5n}{4}$ SBoxes each acting on $4$-bits nibbles. We recognize the SBox from the Present cipher.
This challenge reminded me of **One round crypto** at ECSC2024 but this time with a hash function instead of a cipher.

{{< figure src="/images/meme_alg.jpeg" >}}


## First attempt(s)

### Bouncy

Since this hash function is comprised of one non-linear and 2 linear layer I thought about using a rebound attack :
We want $x \ne y \in \mathbb F_2^{2n}$ s.t $H(x) = H(y)$. To but it in algebraic terms we have:

$$B S(A x) - B S(A y) = 0$$
$$B (S(A x) - S(A y)) = 0$$

or since $B$ is $5n \times n$ (will have big kernel)

$$S(A x) - S(A y) \in \ker B$$

For the rebound we want some differential property of $S$, since its the present SBox we do have some differential at 25%, in particular if we consider the differential space in and out:

$$\forall d_y \in \Delta^S_y, \forall d_z \in \Delta^S_z, \exist y\in \mathbb F_2^4 \text{ s.t } S(y \oplus d_y) = S(y) \oplus d_z$$

Then the inbound differential chains looks like:

$$\Delta_x \xrightarrow A \Delta_y \xrightarrow S \Delta_z \xrightarrow B 0$$

This requires that $d_z \in \ker B$ and $d_y \in \text{Im } A$

Sooooo we need...  $d_z \in \ker B \cap \Delta^S_z$ and $d_y \in \text{Im } A \cap \Delta^S_y$ which turns out... is pretty hard to find, for up to $n=32$ the SAT solver actually found it but it didn't scale and I just couldn't find my inbound otherwise...

### Fun with the ANF

Since the challenge looks mostly algebraic, let's look at the ANF of the Sbox:

```python
from sage.all import *
from sage.crypto.sbox import SBox

def anf(s): # taken from the INRIA symmetric crypto tutorial
    result = []
    for i in range(4):
        result.append(P(s.component_function(1 << i).algebraic_normal_form()))
    return result

S = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
pols = anf(SBox(S))
print(pols)
```

and we get:

```
[x1*x2 + x0 + x2 + x3, x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x2*x3 + x1 + x3, x0*x1*x3 + x0*x2*x3 + x0*x1 + x0*x3 + x1*x3 + x2 + x3 + 1, x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x2 + x0 + x1 + x3 + 1]
```

Here, a few things stand out, first there aren't many terms of degree $3$ but also and thats what I realised at the time, if you substitute $x_1 = x_3 = 0$ then you get:

```
[x0 + x2, 0, x2 + 1, x0 + 1]
```

A perfectly linear SBox ! So in my collision I just have to fix the first two bits in the entrance of each SBox to 0 right ?

Except we have $\cfrac{5n}{4}$ SBoxes and with $2$ bits per SBox =, thats $\cfrac{5n}{2}$ constraints while the input is only $2n$ bits, urgh... Though if you replace the $5$ by a $2$ this solution does work in the end !

I got stuck there for a very long time afterwards...

## Introducing the differential but like not the one you think about...

I discovered the next property a bit by accident, by fiddling with algebraic representation and realised that even though the algebraic degree of the SBox is $3$, for a fixed $\delta \in \mathbb F_2^{2n}$, $H(x + \delta) + H(x)$ is of degree... 2 ??
While both $H(x + \delta)$ and $H(x)$ are degree $3$ ??

Well it actually makes sense, you can see it as differentiating a polynomial thus reducing it's degree by one, rigorously what's happening is that since in $\mathbb F_2$ , $x^2 = x$ the monomials have independent degree $1$ so the differential always cancels at least a variable from each monom.

Well, we now have a MQ system, which... is not meant to be solved directly and is pretty much unusable (I tried linearising it: *bad idea*).

## What to do next ?

Remember the ANF from earlier.. take a good look at it:

```
[x1*x2 + x0 + x2 + x3, x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x2*x3 + x1 + x3, x0*x1*x3 + x0*x2*x3 + x0*x1 + x0*x3 + x1*x3 + x2 + x3 + 1, x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x2 + x0 + x1 + x3 + 1]
```

Well *yeah*, evry monomial of degree $3$ has a $x_0$ innit ?!
That means that by only fixing one bit per SBox the SBox become degree $2$ thus the differential degree $1$ and we can just solve a linear system !!

Well, again, STILL not enough but ...

{{< figure src="/images/end.jpg" >}}


Trust me `:-)`

In fact just like before we'll need $\cfrac{5n}{4}$ constraints for the $1$-bit fix plus $n$ for the solving at the end and unfortunatly $\cfrac{5n}{4} + n \gt 2n$...

But, in a desperate attempt we can try to do the $1$ bit constrain on as many Sbox as we can and look at the resulting polynomial degrees:

```python
from sage.all import *
import random


F2 = GF(2)

n = 64
K = 5
random.seed(0)
A = [ random.choices([0, 1], k = 2 * n) for _ in range(K * n) ]
B = [ random.choices([0, 1], k = K * n) for _ in range(n) ]

S = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

P = BooleanPolynomialRing(2*n,'x')
xs = vector(P.gens()), vector(F2, [random.randint(0, 1) for _ in range(2*n)])

pols = [lambda x0, x1, x2, x3: x1*x2 + x0 + x2 + x3, 
        lambda x0, x1, x2, x3: x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x2*x3 + x1 + x3, 
        lambda x0, x1, x2, x3: x0*x1*x3 + x0*x2*x3 + x0*x1 + x0*x3 + x1*x3 + x2 + x3 + 1, 
        lambda x0, x1, x2, x3: x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x2 + x0 + x1 + x3 + 1]


Af = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n])
Ar = Af.right_kernel_matrix()
nbv = Ar.dimensions()[0]

P = BooleanPolynomialRing(nbv, 'x')

Af2 = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n]) # can onkly have n here instead of 5n/4
Ar2 = Af2.right_kernel_matrix()
dxs = Ar2[0]

def H_pol(state):
    state = matrix(F2, A) * vector(state)
    ns = [0] * len(state)
    for i in range(0, len(state), 4):
        for j in range(4):
            ns[i + j] = pols[j](state[i], state[i + 1], state[i + 2], state[i + 3])
    return vector(ns)

xs = sum(v * ak for v, ak in zip(P.gens(), Ar))

diff_state = list(matrix(F2, B) *(H_pol(xs) + H_pol( xs + dxs)))
print([p.degree() for p in diff_state])
```

we get :

```
[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
```

Well ... all of them are affected, but if you try to solve this using Gröbner-basis, you..... atually **succeed** WTF ? up to like n=128 ???? But fail at n=256 (probably still doable for a big machine).

Solving such a big system (even for n=64) in matter of seconds means there is hidden linearity and... Well I was quite dumb not to see it but its the matrix $B$ mixing the degree $2$... If I remove the matrix mul in the final differential state this becomes clear :

```python
diff_state = list((H_pol(xs) + H_pol( xs + dxs)))
```

gives :

```
[1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, -1, -1, -1, -1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, -1, -1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 1, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 1, 2, 1, 1, 2, 2, 2, 1, 1, 2, 1, 1, 2, 2, 2, 1, 1, 2, 1, 1, 2, 2, 2, 1, 1, 2, 1, 1, 2, 2, 2, 1, 2, 2, 2]
```

And now.......

{{< figure src="/images/stuck.jpeg" >}}


... Yes I did...

But after a few hours I realized that I was still chosing my differential randomly and that this was probably pretty dumb, so looking back at it... If you dont activate the SBoxes well you dont really care about the degree, having that in mind the code for choosing the differential not only should have the first bit of the degree-reduced SBoxes to $0$ but ALSO, ALL the bits of the non degree-reduced SBoxes to $0$.

Thats clearer when looking at the code, the previous choice was:

```python
Af2 = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n]) # can onkly have n here instead of 5n/4
dxs = Af2.right_kernel_matrix()[0]
```

and now:

```python
Af2 = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n] + [A[i] for i in range(K * n)][-n:])
dxs = Af2.right_kernel_matrix()[0]
```

## Putting it all together

Putting it all together and you get the flag : `b7691eedfcb698bf84bcf00e9fae9156f924bc95ecb73b6e0915a87b532549dff0ffbe4095d6cc5511ebbd4fcc293bbd67875657ae37075e13dd706c449a578a`

Here is my ~~quite dirty~~ solve:

```python
from Crypto.Util.number import *
from sage.all import *
from gmo.all import *
import random
from splhash import Splhash

def pack(bits, width):
    return [
        sum((bits[i + j]) << j for j in range(width))
        for i in range(0, len(bits), width)
    ]
F2 = GF(2)

n = 256
K = 5 # 5 in chall

random.seed(0)
A = [ random.choices([0, 1], k = 2 * n) for _ in range(K * n) ]
B = [ random.choices([0, 1], k = K * n) for _ in range(n) ]

H = Splhash(0, n, K)

S = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]

P = BooleanPolynomialRing(2*n,'x')
xs = vector(P.gens()), vector(F2, [random.randint(0, 1) for _ in range(2*n)])

pols = [lambda x0, x1, x2, x3: x1*x2 + x0 + x2 + x3, 
        lambda x0, x1, x2, x3: x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x2*x3 + x1 + x3, 
        lambda x0, x1, x2, x3: x0*x1*x3 + x0*x2*x3 + x0*x1 + x0*x3 + x1*x3 + x2 + x3 + 1, 
        lambda x0, x1, x2, x3: x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x2 + x0 + x1 + x3 + 1]


Af = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n])
Ar = Af.right_kernel_matrix()
nbv = Ar.dimensions()[0]

P = BooleanPolynomialRing(nbv, 'x')

Af2 = matrix(F2, [A[i] for i in range(K * n) if i % 4 == 0][:n] + [A[i] for i in range(K * n)][-n:])
dxs = Af2.right_kernel_matrix()[0]

def H_pol(state):
    state = matrix(F2, A) * vector(state)
    ns = [0] * len(state)
    for i in range(0, len(state), 4):
        if state[i] != 0: print(i)
        for j in range(4):
            ns[i + j] = pols[j](state[i], state[i + 1], state[i + 2], state[i + 3])
    state = vector(ns)
    return vector(state)

xs = sum(v * ak for v, ak in zip(P.gens(), Ar))
diff_state = list(matrix(F2, B) *(H_pol(xs) + H_pol( xs + dxs)))
csts = vector(F2, [pol.constant_coefficient() for pol in diff_state])
pl = Sequence(pol + cs for pol, cs in zip(diff_state, csts))
M, u = pl.coefficients_monomials()

print("solvring", u, flush=True)
print(f"{K = }")
print(f"{n = }")

print(M.dimensions(), M.rank())
us = M.solve_right(csts)

x = vector(F2, [xss.subs({ue: use for ue, use in zip(u, us)}) for xss in xs])
y = x + dxs

x, y = bytes(pack(list(map(int, x)), 8)), bytes(pack(list(map(int, y)), 8))
print("x =", x.hex())
print("y =", y.hex())
print(f"{H(x) == H(y)}")
```
