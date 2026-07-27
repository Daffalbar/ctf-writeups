# Cryptosystem — Crypto Challenge Writeup

**Author:** [Daffalbar](https://github.com/Daffalbar)  
**Category:** Cryptography  
**Difficulty:** Easy  
**Flag:** `THM{Just_s0m3_small_amount_of_RSA!}`

---

## Challenge Description

> We intercepted a communication between Cipher and some 3 associates: Rivest, Shamir and Adleman. We were only able to retrieve a file.
> ORDER: Get the secret key from the recovered file.

---

## Initial Analysis

Nama **Rivest, Shamir, and Adleman** langsung jadi clue utama — ini adalah penemu algoritma **RSA**. Jadi challenge ini pasti berkaitan dengan kriptografi RSA.

Source code yang diberikan:

```python
from Crypto.Util.number import *
from flag import FLAG

def primo(n):
    n += 2 if n & 1 else 1
    while not isPrime(n):
        n += 2
    return n

p = getPrime(1024)
q = primo(p)
n = p * q
e = 0x10001
d = inverse(e, (p-1) * (q-1))
c = pow(bytes_to_long(FLAG.encode()), e, n)
```

---

## Vulnerability Identification

Fokus pada baris ini:

```python
p = getPrime(1024)
q = primo(p)  # ← RED FLAG
```

Fungsi `primo(p)` mencari bilangan prima **terdekat berikutnya setelah p**.

Artinya:
```
p = bilangan prima acak 1024-bit
q = bilangan prima terkecil yang lebih besar dari p
→ |p - q| sangat kecil
→ p ≈ q
→ keduanya mendekati √n
```

Ini adalah **miskonfigurasi klasik RSA** — keamanan RSA bergantung pada sulitnya memfaktorkan `n = p × q`. Ketika `p` dan `q` terlalu berdekatan nilainya, algoritma **Fermat Factorization** dapat memfaktorkan `n` dengan sangat cepat.

---

## Attack: Fermat Factorization

Metode Fermat memanfaatkan fakta bahwa jika `p ≈ q`, maka:

```
n = p × q = a² - b²  = (a-b)(a+b)
```

Dimana:
- `a = (p + q) / 2` → mendekati `√n`
- `b = (q - p) / 2` → sangat kecil

**Algoritma:**
1. Mulai dari `a = ⌈√n⌉`
2. Hitung `b² = a² - n`
3. Cek apakah `b²` adalah perfect square
4. Jika ya → `p = a - b`, `q = a + b`
5. Jika tidak → increment `a` dan ulangi

---

## Solution

```python
from math import isqrt
from Crypto.Util.number import long_to_bytes

# Data dari challenge
n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891

e = 0x10001

c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510

# Step 1: Fermat Factorization
def fermat_factor(n):
    a = isqrt(n) + 1
    b2 = a * a - n
    while True:
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
        b2 = a * a - n

p, q = fermat_factor(n)
print(f"[+] p found: {p}")
print(f"[+] q found: {q}")

# Step 2: Recover private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
print(f"[+] d recovered")

# Step 3: Decrypt
m = pow(c, d, n)
flag = long_to_bytes(m)
print(f"[+] Flag: {flag.decode()}")
```

**Output:**
```
[+] p found: ...
[+] q found: ...
[+] d recovered
[+] Flag: THM{Just_s0m3_small_amount_of_RSA!}
```

---

## Key Takeaways

- RSA aman **hanya jika** `p` dan `q` dipilih secara acak dan independen
- Jika `q = next_prime(p)`, maka `p ≈ q` dan Fermat Factorization berjalan sangat cepat
- Selalu gunakan dua bilangan prima yang **jauh berbeda** nilainya dalam implementasi RSA
- Nama tokoh dalam deskripsi soal CTF sering jadi clue algoritma yang digunakan

---

## References

- [Fermat's Factorization Method — Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
- [RSA Cryptosystem — Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [pycryptodome Documentation](https://pycryptodome.readthedocs.io/)

---

*Writeup by [Daffalbar](https://github.com/Daffalbar)*