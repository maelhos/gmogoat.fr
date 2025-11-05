---
date: '2025-10-28T18:48:09+01:00'
title: 'Two Descent on Elliptic Curve'
draft: true
math: true
tags:
    - Elliptic Curve
    - Crypto
---

## Motivation

While replaying challenges from prior FCSC, I ended up trying to solve the challenge [Surface](https://hackropole.fr/fr/challenges/crypto/fcsc2022-crypto-surface/), in this challenge we *just* have to solve the following equation over the rationals :

$$\begin{cases} a^2 + b^2 = c^2 \\ ab = 20478\end{cases}$$

It turns out that such pair $(a, b) \in \mathbb Q^2$ are called congruent numbers and finding those is equivalent to finding some rational point on an elliptic curve, more specifically :

if $(a, b, c) \in \mathbb Q^3$ is a solution to

$$\begin{cases} a^2 + b^2 = c^2 \\ \frac 1 2 ab = n\end{cases}$$

For some fixed $n$ then, setting $x = \cfrac{n(a + c)}{b}$ and $y = \cfrac{2n^2(a + c)}{b^2}$ then :

$$y^2 = x^3 - n^2 x$$

And if one finds a rational point of this elliptic curve then they may use the previous parametrization to find a solution to our initial problem.

Easy enough right ? Elliptic curves have been studied enough that this shouldn't be a problem right ?

```python
n = 20478 // 2
E = EllipticCurve(QQ, [-n**2, 0])
print(E.gens())
```

annnnnd :

```text
RuntimeError: Unable to compute the rank, hence generators, with certainty (lower bound=0, generators found=()).  This could be because Sha(E/Q)[2] is nontrivial.
Try increasing descent_second_limit then trying this command again.
```

Shoot.

### The Ugly

Let's just try and increase the thingy then... spoiler : I've been told that you can solve using *mwrank* in sage in something like 10 hours with a large sieve bound...

### The bad

Then if we use the special credit card technique or use a free online version of **Magma** we get the awaited result in just.... **4.7 sec** ON THE ONLINE VERSION !!

```python
def free_QQ_EC_gen(C):
    magma_shot = f"P<x>:=PolynomialRing(RationalField());E:=EllipticCurve([{str(C.ainvs())[1:-1]}]);print Generators(E);"
    ret = magma_free(magma_shot)

    if not ":" in ret: return []
    
    gen_str = ret.replace(" ", "").split("\n")[0].strip()[1:-1]
    gens = [C([QQ(e) for e in k[1:-1].split(":")]) for k in gen_str.split(",")]
    return gens

n = 20478 // 2
E = EllipticCurve(QQ, [-n**2, 0])
G = free_QQ_EC_gen(E)[-1]
print(G)
```

and we get :

```text
(737343773862301088045509418793921869066076/10893159238600577313677917228652511841 : 625862116444448047393458603029555713662450024330982757172975030/35952639365198540562613869494033558726733788804390127889 : 1)
real    0m4,791s
user    0m0,884s
sys     0m0,914s
```

Since the obscure black box technology behind Magma is much faster we must doing something wrong...

### The good

As mentioned by multiple (way more knowledgeble) people on the Cryptohack discord, one can use Heegner point method in *Pari* with :

```python
sage: %time pari.ellheegner(pari.ellinit([-(20478//2)**2, 0]))
CPU times: user 1h 2min 54s, sys: 2.67 s, total: 1h 2min 57s
Wall time: 1h 2min 52s
[282959610435444133053419204432698312602025/20373367074202226028933855008293414081, 101697826622235966740266840753050504440060542552224371758641460/91958994752272050466781940295842999799221523355897410271]
```

that still took like 1 hour on my machine...

## Why ?

There exist a variety of algorithm for finding rational points on elliptic curves or more generally algebraic curves. Sadly, not enough of them have usable open-source implementation :

Sage :

- 2-descent via **mwrank**
- Some kind of sieving for algebraic curves `sage.schemes.projective.projective_rational_point.sieve`

Pari :

- 2-descent
- Heegner point

Magma :

- 2, 3, 4, 5-descent
- Heegner point
- Elikes LLL method

(Big thanks to @grhkm, @hellman, @genni for their explanations and writeups)

## Can we do better ?

Well all we have to do is just implement right ? The papers are just there...

{{< figure src="/images/christ.webp" >}}

Problem here is just big skill issue on my side 🗿. So here is my tale of trying to implement these algorithm.

### The basics of 2-descent

Before trying anything new and because the method we want to later implement rely on *2-descent*, let's start with that because boy do we have some things to do already.

#### The Setup

Let's start with an Elliptic curve $E(\mathbb Q)$ with full 2-torsion to make things easier, what that means is if we take a short Weirstrass form :

$$y^2 = x^3 + ax + b$$

Then the polynomial $x^3 + ax + b$ has $3$ roots $e_1$, $e_2$ and $e_3$ over $\mathbb Q$.

**> Haven't we found the point we so desired yet then ?? Was easy after all...**

Well... Not really even though $(e_i, 0)$ are indeed points they are just torsion points on the curve they are not of any interest as they live alone in their own subgroup (by Mordell-Weil theorem $E(\mathbb Q) = E_{tors} \times \mathbb Z^r$)

In our case we are looking for non trivial-points, meaning those outside $E_{tors}$ (this assumes $r>0$ but we won't worry about the rank for this time).

Do also note that recovering all the torsion points (not only 2-torsion) is easy thanks to the Nagell–Lutz theorem.

**> Isn't the assumption that our curve has full 2-torsion a bit strong ?**

Yes and no, most paper just tell you that in the non full 2-torsion case, there exist some extension of $\mathbb Q$ s.t $x^3 + ax + b$ splits and everything works the same, in practice it's less trivial to implement but our case of interest (the curve for the *Surface* challenge) is full 2-torsion so let's start from there.

We may also consider that the curve has coefficients over $\mathbb Z$, by realizing that our curve is isomorphic to

$$y^2 = x^3 + u^4 ax + u^6 b$$

Via the following isomorphism $\phi(x, y) = (x u^{-2}, y u^{-3})$, so all we have to do is choose $u$ s.t the denominator of $a$ and $b$ divides $u$ (there is actually a cannonical way of doing that while trying to keep the coefficients as small as possible : minimal models).

#### The "descent"

The descent procedure that I present here might seem a little "had-hoc" but I do not understand the complicated math and fancy diagrams required to have the mathematical reasons for it 🗿 so let's stick to and easy construction.

Let's first consider a projective point on the curve $(x : y : z)$ with $(x, y, z) \in \mathbb Z^3$ (we can always scale $z$ s.t $x, y$ lies in $\mathbb Z$)

$$y^2 = (x - e_1 z^2)(x - e_2 z^2)(x - e_3 z^2)$$

We can then decompose each coordinate into a product of a square-free rational times a square, we will be doing that for each $x - e_i z^2$ :

$$\begin{cases}b_1 z_1^2 = x - e_1 z^2 \\ b_2 z_2^2 = x - e_2 z^2 \\ b_3 z_3^2 = x - e_3 z^2\end{cases}$$

with $b_i \in \mathbb Z^* \setminus (\mathbb Z^*)^2$ and $z_i \in \mathbb Z$

Then we cancel out the $x$:

$$\begin{cases}b_1 z_1^2 - b_2 z_2^2 = z^2 (e_2 - e_1) \\ b_1 z_1^2 - b_3 z_3^2 = z^2 (e_3 - e_1)\end{cases}$$

Ok so now we reduced our problem to finding even more random variables... but fortunatly we can do a bit of number theory to deal with the $b_i$.

### Not the $b$'s

By using the fact that $\ gcd(a, b) | ka + lb$ ; notice that $\gcd(x - e_1 z^2, x - e_2 z^2) | (e_2 - e_1) z^2$ and $\gcd(x - e_1 z^2, x - e_2 z^2) | (e_1 - e_2) x$.

But we also have that if $a | b$ and $a | c$ then  $a | \gcd(b, c)$ so $\gcd(x - e_1z^2, x - e_2 z^2) | \gcd((e_2 - e_1) z^2, -(e_2 - e_1) x)$. Notice that w.l.o.g we can consider that $\gcd(x, z^2) = 1$ otherwise it means $z$ is not minimal (basically we can consider $x/z^2$  irreducible as a consequence of the projective representation).

So finally : $$\gcd(x - e_1z^2, x - e_2 z^2) | e_2 - e_1$$
We may generalize $\forall (i, j) \in [\\![1, 3]\\!], i \ne j$ : $$\gcd(x - e_iz^2, x - e_j z^2) | e_i - e_j$$

Now we come back to the initial definition of the $b_i$'s and plug it in the elliptic curve equation, we get :

$$y^2 = b_1 b_2 b_3 (z_1 z_2 z_3)^2$$

which means despite each $b_i$ being square-free, their **product must be a square**.

Let's consider some prime $p$ and some $i \in [\\![1, 3]\\!]$ s.t $p | b_i$ then because $b_i$ is square-free, $v_p(b_i) = 1$ (the exponent of $p$ in the prime decomposition of $b_i$ is $1$) but $b_1 b_2 b_3$ is a square ! That means that $p$ must devide exactly one of the other $b_i$, formally : $\exists j \in [\\![1, 3]\\!] \setminus \{i\}$ s.t $p | b_j$.

And now we can use our previous property because $p | \gcd(b_i, b_j)$ so $p | \gcd(b_i z_i^2, b_j z_j^2)$ which by definition means $p | \gcd(x - e_i z^2, x - e_j z^2)$ and finally :

$$p | e_i - e_j$$

which in turns mean :

$$b_i | (e_1 - e_2)(e_2 - e_3)(e_1 - e_3)$$

**Conclusion :** we can iterate threw the square free divisors of $(e_1 - e_2)(e_2 - e_3)(e_1 - e_3)$, for $b_1$ and $b_2$ and take $b_3$ as the square-free part of $b_1 b_2$ : we only have a finite amounts of possibilities for the 🐝!

### Ternary quadratic forms

Ok so now we consider that in our program we'll just iterate over the values for $b_i$ so from now on, I consider them as **fixed**.

#### Building it

Let's continue from the previous system of equations :

$$\begin{cases}b_1 z_1^2 - b_2 z_2^2 = z^2 (e_2 - e_1) \\ b_1 z_1^2 - b_3 z_3^2 = z^2 (e_3 - e_1)\end{cases}$$

by dividing the equation to cancel the $z$ variable we get :

$$\cfrac{b_1 z_1^2 - b_2 z_2^2}{b_1 z_1^2 - b_3 z_3^2} = \cfrac{e_2 - e_1}{e_3 - e_1}$$

We can first simplify the fixed fraction (make irreducible) : $\cfrac{e_2 - e_1}{e_3 - e_1} = \cfrac{r_2}{r_3}$

and we get our desired **ternary quadratic form** wich is already in **diagonal form** by cross multiplying :

$$(r_3 b_1 - r_2 b_1)z_1^2 - r_3 b_2 z_2^2 + r_2 b_3 z_3^2 = 0$$

#### Reducting it

Let's consider a generic ternary quadratic form $ax^2 + by^2 + cz^2 = 0$, the important algebraic fact about this equation is that it has **genus 0** which means **Hasse principle** applies, but before going down that road let's simplify things a bit :

- First if $g = \gcd(a, b, c)$ is non trivial we can divide $a, b, c$ by $g$
- If for a prime $p$, $p^2 | a$ then see that if $x', y, z$ is a solution to $\frac{a}{p^2}{x'}^2 + by^2 + cz^2 = 0$ then $x := px'$ is a solution to the original equation
- If for a prime $p$, $p | a$ and $p | b$ then we can multiply $a, b$ and $c$ by $p$ and apply the previous simplification to $a$ and $b$. This way a prime never divides more than one of the coefficient.

By symetry on the roles of $a, b$, and $c$ one may apply these rules until $a, b$ and $c$ are pairwise coprime and $abc$ is square-free.

#### Soving it

as mentioned previously we then make use the the **Hasse principle** which if it applies (to a given curve) that if the equation is locally soluble over every $\mathbb Q_p$ and over $\mathbb R$ then it's soluble over $\mathbb Q$.

Practically this means that if its soluble over $\mathbb R$ which in our case just means $a, b$ and $c$ dont all have the same sign then we can solve $\mod p$ for multiple $p$ and pieces these solutions together using the chinese reminder theorem.

In particular, if we take $p$ a prime number s.t $p | a$ then :

$$by^2 + cz^2 \equiv 0 \pmod p$$

Meaning

$$\left(\cfrac{y}{z}\right)^2 \equiv \cfrac{-c}{b} \pmod p$$

Then we can check the existence of such modular square root using Euler's criterion and perform the square root using Tonelli-Shanks. The first interesting thing here is that if there is no suare root then we know for sure the quadratic form has no solution.

In practice this is very usefull as it helps narowing down the set of $b_i$ that are worth keeping.

If such root exist ($r^2 \equiv \frac{-c}{b} \pmod p$) then :

$y - rz \equiv 0 \pmod p$

Doing that for several $p$ we acumulate relations which we can combine to get something of the form :

$$\alpha x + \beta y + \gamma z \equiv 0 \pmod{abc}$$

In practice because of the problems with $p = 2$ and a million boring disjunction of case later we can even get :

$$\alpha x + \beta y + \gamma z \equiv 0 \pmod{4abc}$$

*But... This is only a necessary condition ?* Yes... but there is more to it, we actually know that the solution space of quadratic forms is ... you gessed it ... a lattice !

{{< figure src="/images/LLL.jpg" >}}

In particular the smallest vector satisfying $(1)$, will yield a solution to the original equation.

#### We want moooooooooooore

So we did indeed found a solution, but unsurprisingly, because we have a single equation and 3 free variables it is not unique. It's still worth trying it before down parametrization though.

Let's take an initial solution $ax_0^2 + by_0^2 + cz_0^2 = 0$, then taking $x = x_0 W + U$, $y = y_0 W + V$ and $z = z_0 W$ we get :

$$\begin{align*}0 &= a (x_0W + U)^2 + b(y_0W + V)^2 + c W^2 z_0^2 \\ &= a x_0^2 W^2 + 2ax_0U + a U^2 + by_0^2 W^2 + 2by_0WV + bV^2 + cW^2 z_0^2 \\ &= 2ax_0U + aU^2 + bV^2 + 2by_0WV\end{align*}$$

So it suffice to take $W = \cfrac{aU^2 + bV^2}{-2by_0V}$ and we have a parametrization !

*Side note :* John Cremona's paper introduces an other parametrization (which is just a sub-parametrization of this one) with lower discriminant meaning it still parametrizes the same solution space but it does so with $Q'_i(U, V)$ being "generally smaller" than $Q_i(U, V)$ which is desirable for sieving afterwards.

**Conclusion :** for a ternary quadratic form $f$ we can find $Q_i(U, V) = r_iU^2 + s_i UV + t_i V^2$ with $i \in [\\![1, 3]\\!]$, s.t $(Q_1(U, V), Q_2(U, V), Q_3(U, V))$ is the set of solutions to $f(x, y, z) = 0$.

### Up the genus

Now we just reinject the previous parametrization for the quadratic form in the first equation of our system :

$$b_1 Q_1(U, V)^2 - b_2 Q_2(U, V)^2 = z^2 (e_2 - e_1)$$

One can chec that $\forall (U, V) \in \mathbb Z^2, e_2 - e_1 | b_1 Q_1(U, V)^2 - b_2 Q_2(U, V)^2$ and because $Q_1$ and $Q_2$ are homogeneous we just have an equation for a hyperelliptic curve of genus $2$ or $3$ in projective coordinate !

We can now use some form of sieving to find points or do higer descent.

## Conclusion

I am currently working on an implementation based on FLINT.
If I have not released it yet, I'll make the implem open-source soon.
There are a few things I'd like to be implemented :

- Factorization book-keeping
- The 2-descent itself
- Ternary quadratic form resolution (idealy the better algo that does not factor nor use LLL)
- Some solubility criterion on hyper-elliptic curve
- Some form of sieving either specific to hyper-elliptic curve or generic like in sage

*This is a draft, I am no expert, do tell me if I wrote something wrong or unclear...*
