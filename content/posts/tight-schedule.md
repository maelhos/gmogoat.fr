---
date: '2025-08-12T19:48:50+02:00'
title: 'Tight Schedule - FCSC 2024'
math: true
tags:
    - CTF
    - FCSC2024
    - Crypto
---

## Overview

In this chall we are presented with a cipher entierely based on the AES key schedule derivation function.
Seing such a "well known" construction hints us towards the literature.

## The paper

Indeed, one paper ["New Representations of the AES Key Schedule"](https://eprint.iacr.org/2020/1253.pdf) gives us most of what we need to solve.

## Cipher description

### AES Key derivation

Let's denote by $D_i(k_0, k_1, \cdots, k_{15}) = (s_0, s_1, \cdots, s_{15})$ the AES key-derivation function on the 16 bytes of the key with the $i$-th RCON (taking $i=0$ being no round constant).

The full description of $D_i$ is a bit cumbersome to fully write down but each of the $s_i$ is a linear combinaison in $\text{GF}(2^8)$ (xor) of multiple $k_i$, $S[k_{12}], S[k_{13}], S[k_{14}], S[k_{15}]$ and $c_i$ where $c_i$ are the *RCON* constants and **S** is the AES SBox.

Graphically the AES derivation function looks like :
{{< figure src="/images/ks_normal.png" >}}

### The cipher

Then the cipher simply derives round keys from the original key $k$ just like AES :

$k_i = (D_i \circ D_{i-1} \circ \cdots \circ D_2 \circ D_1)(k)$

The round function is then $R_i(B) = R_0^5(B \oplus k_i)$
And then the ciphertext $C$ can be expressed from the plaintext $P$ as :

$C = (R_9 \circ R_8 \circ \cdots \circ R_0)(P) \oplus k_{10}$

The main weakness here is the low number of SBox in the key derivation and the particular linear structure that propagates threw the cipher/

## Exploiting the paper's idea

The paper essentialy describes a way to "untwist" the key schedule and find a representation aka a morphisomorphismism that makes it so that each of the four 32-bit words of each key act independently.

The key thing her is that this isomorphism is a **linear function**, that we can indeed represent by a matrix and as the *iso* suggest, it is invertible.

And under this isomorphism the key schedule looks like this :
{{< figure src="/images/ks_basis.png" >}}

Because our cipher is only comprised of AES key derivation rounds and xor with other derived keys, if we "change basis" to using the isomorphism each block of 32 bit acts independently, we can test this by running :

```python
def morph(l):
    k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15 = l
    return [k15,                 #s0
            k14 ^ k10 ^ k6 ^ k2, #s1
            k13 ^ k5,            #s2
            k12 ^ k8,            #s3

            k14,                 #s4
            k13 ^ k9 ^ k5 ^ k1,  #s5
            k12 ^ k4,            #s6
            k15 ^ k11,           #s7

            k13,                 #s8
            k12 ^ k8 ^ k4 ^ k0,  #s9
            k15 ^ k7,            #s10
            k14 ^ k10,           #s11

            k12,                 #s12
            k15 ^ k11 ^ k7 ^ k3, #s13
            k14 ^ k6,            #s14
            k13 ^ k9]            #s15

def unmorph(l):
    s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15 = l
    return [s9 ^ s6 ^ s3 ^ s12,
            s5 ^ s2 ^ s15 ^ s8,
            s1 ^ s14 ^ s11 ^ s4,
            s13 ^ s10 ^ s7 ^ s0,

            s6 ^ s12,
            s2 ^ s8,
            s4 ^ s14,
            s0 ^ s10,
            
            s3 ^ s12,
            s8 ^ s15,
            s4 ^ s11,
            s0 ^ s7,
            
            s12,
            s8,
            s4,
            s0]

assert unmorph(morph(k)) == k
assert morph(unmorph(k)) == k

p0 = os.urandom(4) + b"\x00" * 12
p1 = os.urandom(4) + b"\x00" * 12

T1 = TightSchedule(bytes(unmorph(p0)))
T2 = TightSchedule(bytes(unmorph(p1)))

P = os.urandom(16)
print(morph(T1.encrypt(P)))
print(morph(T2.encrypt(P)))
```

which gives :

```python
[158, 26, 238, 6, 109, 180, 134, 118, 161, 162, 243, 21, 121, 190, 182, 230]
[158, 26, 238, 6, 109, 180, 134, 118, 160, 171, 167, 43, 121, 190, 182, 230]
```

and only the third block has changed under the morphism !
So then its just a matter of four 32-bit bruteforces

## The solution

### Nothing better than C++

{{< figure src="/images/meme_cpp.png" >}}

Because **python** is going to be slow and CPU designers have done great things to include cryptography stuff, let's use `C++`.

In particular we can benefit from the `_mm_aeskeygenassist_si128` intrinsic to implement a very fast version of the cipher :

First the key ~~stolen~~ found on the internet :

```cpp
template<auto R>
inline state aes_128_key_assist(state prev_key) 
{
    state temp = _mm_aeskeygenassist_si128(prev_key, R);
    temp = _mm_shuffle_epi32(temp, 0xff);
    state next_key = _mm_slli_si128(prev_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    next_key = _mm_slli_si128(next_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    next_key = _mm_slli_si128(next_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    return _mm_xor_si128(next_key, temp);
}
```

Then the cipher itself in a couple of lines

```cpp
#define TSRound(p, k, rcon) do {p = _mm_xor_si128(p, k); \
                            for (uint8_t j = 0; j < 5; j++) \
                                p = aes_128_key_assist<0>(p); \
                            k = aes_128_key_assist<rcon>(k); } while (0)

state TSencrypt(state s, state k)
{
    state p = s;
    TSRound(p, k, RCON[1]);
    TSRound(p, k, RCON[2]);
    TSRound(p, k, RCON[3]);
    TSRound(p, k, RCON[4]);
    TSRound(p, k, RCON[5]);
    TSRound(p, k, RCON[6]);
    TSRound(p, k, RCON[7]);
    TSRound(p, k, RCON[8]);
    TSRound(p, k, RCON[9]);
    TSRound(p, k, RCON[10]);
    p = _mm_xor_si128(p, k);

    return p;
}
```

The morphism and it's inverse as described by the paper :

```cpp
void morph(uint8_t* out, uint8_t* in)
{
    out[0]  = in[15];
    out[1]  = in[14] ^ in[10] ^ in[6] ^ in[2];
    out[2]  = in[13] ^ in[5];
    out[3]  = in[12] ^ in[8];
    out[4]  = in[14];
    out[5]  = in[13] ^ in[9] ^ in[5] ^ in[1];
    out[6]  = in[12] ^ in[4];
    out[7]  = in[15] ^ in[11];
    out[8]  = in[13];
    out[9]  = in[12] ^ in[8] ^ in[4] ^ in[0];
    out[10] = in[15] ^ in[7];
    out[11] = in[14] ^ in[10];
    out[12] = in[12];
    out[13] = in[15] ^ in[11] ^ in[7] ^ in[3];
    out[14] = in[14] ^ in[6];
    out[15] = in[13] ^ in[9];       
}

void unmorph(uint8_t* out, uint8_t* in)
{
    out[0]  = in[9] ^ in[6] ^ in[3] ^ in[12];
    out[1]  = in[5] ^ in[2] ^ in[15] ^ in[8];
    out[2]  = in[1] ^ in[14] ^ in[11] ^ in[4];
    out[3]  = in[13] ^ in[10] ^ in[7] ^ in[0];
    out[4]  = in[6] ^ in[12];
    out[5]  = in[2] ^ in[8];
    out[6]  = in[4] ^ in[14];
    out[7]  = in[0] ^ in[10];
    out[8]  = in[3] ^ in[12];
    out[9]  = in[8] ^ in[15];
    out[10] = in[4] ^ in[11];
    out[11] = in[0] ^ in[7];
    out[12] = in[12];
    out[13] = in[8];
    out[14] = in[4];
    out[15] = in[0];    
}
```

And finally the attack made up of the four 32-bit BFs :

```cpp
int main()
{
    const char plaintext[] = "0dfa4c6052fb87ef0a8f03f705dd5101";
    const char ciphrtext[] = "d4ed19e0694101b6b151e11c2db973bf";
    uint8_t pt[16];
    uint8_t ct[16];
    hex_to_bytes((uint8_t*)pt, (char*)plaintext);
    hex_to_bytes((uint8_t*)ct, (char*)ciphrtext);

    uint8_t ct_morph[16];
    uint8_t enc_bytes[16];
    morph(ct_morph, ct);

    uint8_t key[16] = {0};
    uint8_t key_bf[16] = {0};

    uint32_t* key_bf_blck = (uint32_t*)key_bf;
    
    uint32_t* ct_morph_blck = (uint32_t*)ct_morph;
    state state_pt = _mm_loadu_si128((state*)pt);

    uint8_t morph_enc[16];
    uint32_t* morph_enc_blck = (uint32_t*)morph_enc;

    printf("BF first part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[2] == ct_morph_blck[2])
            break;
        key_bf_blck[0]++;
    }
    
    printf("BF second part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[3] == ct_morph_blck[3])
            break;
        key_bf_blck[1]++;
    }

    printf("BF third part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[0] == ct_morph_blck[0])
            break;
        key_bf_blck[2]++;
    }

    printf("BF last part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[1] == ct_morph_blck[1])
            break;
        key_bf_blck[3]++;
    }

    printf("KEY =");
    for (uint8_t i = 0; i < 16; i++)
        printf("%02x", key[i]);
    printf("\n");

    return 0;
}
```

Running it :

```sh
>>> time ./solve
BF first part
BF second part
BF third part
BF last part
```

## The End

With this we can recover the main key wich is `6c08d6d62cce26530b3f22b34c40995a`

And get our flag :

```python
from Crypto.Cipher import AES

flag_enc = bytes.fromhex("653ec0cdd7e3a98c33414be8ef07c583d87b876afbff1d960f8f43b5a338e9ff96d87da4406ebe39a439dab3a84697d40c24557cd1ea6f433053451d20ce1fbf191270f4b8cc7891f8779eb615d35c9f")
key = bytes.fromhex("6c08d6d62cce26530b3f22b34c40995a")
iv = bytes.fromhex("cd31cb6e6ded184efbb9a398e31ffdbb")

E = AES.new(key, AES.MODE_CBC, iv = iv)
print(E.decrypt(flag_enc))
```

Hurray `FCSC{1efc507f987a19a5925b85e8dcc78c7011ef22e8f23bd7ebadf6aff3ed1416f9}` !!!

## Full code of "solve.cpp"

Don't forget to use `march=native` for intrisics

```cpp
#include <stdio.h>
#include <wmmintrin.h>
#include <immintrin.h>
#include <stdint.h>

typedef __m128i state;
constexpr uint8_t RCON[] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void hex_to_bytes(uint8_t* bytes, char* hex_string) 
{
    for (int i = 0; i < 16; ++i)
        sscanf(hex_string + 2 * i, "%2hhx", &bytes[i]);
}

state hex_to_m128i(char* hex_string) 
{
    uint8_t bytes[16];
    hex_to_bytes(bytes, hex_string);
    return _mm_loadu_si128((state*)bytes);
}

void print_m128i_hex(state value) 
{
    uint8_t bytes[16];
    _mm_storeu_si128((state*)bytes, value);

    for (int i = 0; i < 16; ++i)
        printf("%02x", bytes[i]);
    
    printf("\n");
}

template<auto R>
inline state aes_128_key_assist(state prev_key) 
{
    state temp = _mm_aeskeygenassist_si128(prev_key, R);
    temp = _mm_shuffle_epi32(temp, 0xff);
    state next_key = _mm_slli_si128(prev_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    next_key = _mm_slli_si128(next_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    next_key = _mm_slli_si128(next_key, 4);
    next_key = _mm_xor_si128(next_key, prev_key);
    return _mm_xor_si128(next_key, temp);
}

#define TSRound(p, k, rcon) do {p = _mm_xor_si128(p, k); \
                            for (uint8_t j = 0; j < 5; j++) \
                                p = aes_128_key_assist<0>(p); \
                            k = aes_128_key_assist<rcon>(k); } while (0)

state TSencrypt(state s, state k)
{
    state p = s;
    TSRound(p, k, RCON[1]);
    TSRound(p, k, RCON[2]);
    TSRound(p, k, RCON[3]);
    TSRound(p, k, RCON[4]);
    TSRound(p, k, RCON[5]);
    TSRound(p, k, RCON[6]);
    TSRound(p, k, RCON[7]);
    TSRound(p, k, RCON[8]);
    TSRound(p, k, RCON[9]);
    TSRound(p, k, RCON[10]);
    p = _mm_xor_si128(p, k);

    return p;
}

void morph(uint8_t* out, uint8_t* in)
{
    out[0]  = in[15];
    out[1]  = in[14] ^ in[10] ^ in[6] ^ in[2];
    out[2]  = in[13] ^ in[5];
    out[3]  = in[12] ^ in[8];
    out[4]  = in[14];
    out[5]  = in[13] ^ in[9] ^ in[5] ^ in[1];
    out[6]  = in[12] ^ in[4];
    out[7]  = in[15] ^ in[11];
    out[8]  = in[13];
    out[9]  = in[12] ^ in[8] ^ in[4] ^ in[0];
    out[10] = in[15] ^ in[7];
    out[11] = in[14] ^ in[10];
    out[12] = in[12];
    out[13] = in[15] ^ in[11] ^ in[7] ^ in[3];
    out[14] = in[14] ^ in[6];
    out[15] = in[13] ^ in[9];       
}

void unmorph(uint8_t* out, uint8_t* in)
{
    out[0]  = in[9] ^ in[6] ^ in[3] ^ in[12];
    out[1]  = in[5] ^ in[2] ^ in[15] ^ in[8];
    out[2]  = in[1] ^ in[14] ^ in[11] ^ in[4];
    out[3]  = in[13] ^ in[10] ^ in[7] ^ in[0];
    out[4]  = in[6] ^ in[12];
    out[5]  = in[2] ^ in[8];
    out[6]  = in[4] ^ in[14];
    out[7]  = in[0] ^ in[10];
    out[8]  = in[3] ^ in[12];
    out[9]  = in[8] ^ in[15];
    out[10] = in[4] ^ in[11];
    out[11] = in[0] ^ in[7];
    out[12] = in[12];
    out[13] = in[8];
    out[14] = in[4];
    out[15] = in[0];    
}

int main()
{
    const char plaintext[] = "0dfa4c6052fb87ef0a8f03f705dd5101";
    const char ciphrtext[] = "d4ed19e0694101b6b151e11c2db973bf";
    uint8_t pt[16];
    uint8_t ct[16];
    hex_to_bytes((uint8_t*)pt, (char*)plaintext);
    hex_to_bytes((uint8_t*)ct, (char*)ciphrtext);

    uint8_t ct_morph[16];
    uint8_t enc_bytes[16];
    morph(ct_morph, ct);

    uint8_t key[16] = {0};
    uint8_t key_bf[16] = {0};

    uint32_t* key_bf_blck = (uint32_t*)key_bf;
    
    uint32_t* ct_morph_blck = (uint32_t*)ct_morph;
    state state_pt = _mm_loadu_si128((state*)pt);

    uint8_t morph_enc[16];
    uint32_t* morph_enc_blck = (uint32_t*)morph_enc;

    printf("BF first part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[2] == ct_morph_blck[2])
            break;
        key_bf_blck[0]++;
    }
    
    printf("BF second part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[3] == ct_morph_blck[3])
            break;
        key_bf_blck[1]++;
    }

    printf("BF third part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[0] == ct_morph_blck[0])
            break;
        key_bf_blck[2]++;
    }

    printf("BF last part\n");
    while (1)
    {
        unmorph(key, key_bf);
        state enc = TSencrypt(state_pt, _mm_loadu_si128((state*)key));
        _mm_storeu_si128((state*)enc_bytes, enc);
        morph(morph_enc, enc_bytes);
        if (morph_enc_blck[1] == ct_morph_blck[1])
            break;
        key_bf_blck[3]++;
    }

    printf("KEY =");
    for (uint8_t i = 0; i < 16; i++)
        printf("%02x", key[i]);
    printf("\n");

    return 0;
}
```
