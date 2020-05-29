from paillier.util import lcm
import secrets
import libnum
import math


class PaillierText:
    def __init__(self, val, n):
        self.val = val
        self.n = n

    def __add__(self, other):
        return PaillierText((self.val * other.val) % (self.n * self.n), self.n)

    def __mul__(self, other):
        if not isinstance(other, int):
            raise TypeError(
                "Multiplication of encrypted paillier text must be with an int"
            )

        return PaillierText(pow(self.val, other, self.n * self.n), self.n)

    __rmul__ = __mul__

    def __repr__(self):
        return str(self.val)


class PaillierEncryptor:
    def __init__(self, p=None, q=None):
        self.p = p if p is not None else libnum.generate_prime(512)
        self.q = q if q is not None else libnum.generate_prime(512)

        if self.q == self.p:
            self.q = libnum.generate_prime(512)

        n = self.p * self.q
        lbd = lcm(self.p - 1, self.q - 1)

        n2 = n * n

        g = secrets.randbelow(n2 - 1) + 1

        l_val = self._l(pow(g, lbd, n2), n)

        while not libnum.has_invmod(l_val, n):
            g += 1
            if g == n2:
                g = 1
            l_val = self._l(pow(g, lbd, n2), n)

        gMu = libnum.invmod(l_val, n)

        self.public_key = (n, g)
        self.private_key = (lbd, gMu)

    def _l(self, x, n):
        return (x - 1) // n

    def encrypt(self, m):
        n = self.public_key[0]
        g = self.public_key[1]

        if m > n:
            raise ValueError(f"Message must be smaller than n={n}")

        r = secrets.randbelow(n - 1) + 1

        c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

        return PaillierText(c, n)

    def decrypt(self, c):
        lbd = self.private_key[0]
        gMu = self.private_key[1]
        n = self.public_key[0]

        return (self._l(pow(c.val, lbd, n * n), n) * gMu) % n
