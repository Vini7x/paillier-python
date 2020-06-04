from paillier.util import lcm
import secrets
import libnum
import math


class PaillierText:
    """
    Representation of Paillier Encrypted text.
    
    Able to run two mathematical operations:
    Addition (+): Adds two Pailler Encrypted numbers and the result will be another object of this class
    Multiplication (*): Multiply this encrypted value with a plain-text value, must be an int.
    """

    def __init__(self, val, n, precision=0):
        self.val = val
        self.n = n
        self.precision = precision

    def __add__(self, other):
        return PaillierText(
            (self.val * other.val) % (self.n * self.n), self.n, self.precision
        )

    def __mul__(self, other):
        if not isinstance(other, int):
            if not isinstance(other, float):
                raise TypeError(
                    "Multiplication of encrypted paillier text must be with either an int or a float"
                )
            else:
                pot = pow(10, self.precision)
                num = other * pot
                dem = pow(pot, -1, self.n)
                n2 = self.n * self.n

                return PaillierText(
                    pow(pow(self.val, num, n2), dem, n2), self.n, self.precision
                )

        return PaillierText(
            pow(self.val, other, self.n * self.n), self.n, self.precision
        )

    __rmul__ = __mul__

    def __repr__(self):
        return str(self.val)


class PaillierEncryptor:
    """
    Default Paillier Encryptor.
    p and q can be specified, but if not, it will generate a random 512 bit prime number.
    """

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

    def encrypt(self, m: int, precision=0) -> PaillierText:
        """
        Input:
            m: the value to encrypt, must be an int
            precision: Floating point precision, unnecessary if only using ints
        Output:
            A PaillierText object representing the encrypted value m
        """
        n = self.public_key[0]
        g = self.public_key[1]

        if m > n:
            raise ValueError(f"Message must be smaller than n={n}")

        r = secrets.randbelow(n - 1) + 1

        c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)

        return PaillierText(c, n, precision)

    def decrypt(self, c: PaillierText) -> int:
        """
        Input:
            c: the value to decrypt, must be a PaillierText object
        Output:
            The decrypt int value
        """
        lbd = self.private_key[0]
        gMu = self.private_key[1]
        n = self.public_key[0]

        return (self._l(pow(c.val, lbd, n * n), n) * gMu) % n


class PaillierEncryptorFloat(PaillierEncryptor):
    """
    A PaillierEncryptor adapted for floating numbers and negative ones.
    Negative numbers work by checking if the number is over a threshold,
    if so it means that it looped back to n and the value is subtracted by n.
    Floating points simply multiply/divide by 10 multiplied by a precision value (default: 4).
    
    Arguments:
        precision: the precision of the floating numbers.
        negative_threshold: the threshold to define a number negative, in value of n/4, e.g. 2 means that
                            numbers over n/2 (n/(2/4)) are considered negative.
    """

    def __init__(self, precision=4, negative_threshold=2, p=None, q=None):
        super().__init__(p=p, q=q)
        self._negthresh = int(self.public_key[0] * (negative_threshold / 4))
        self._precision = int(pow(10, precision))
        self._precision_num = precision

    def encrypt(self, m) -> PaillierText:
        """
        Input:
            m: the value to encrypt, must be a float or int
        Output:
            A PaillierText object representing the encrypted value m
        """
        int_val = int(m * self._precision)
        return super().encrypt(int_val, self._precision_num)

    def decrypt(self, c: PaillierText) -> float:
        """
        Input:
            c: the value to decrypt, must be a PaillierText object
        Output:
            The decrypt float value
        """
        raw_val = super().decrypt(c)
        if raw_val > self._negthresh:
            raw_val = raw_val - self.public_key[0]
        float_val = raw_val / self._precision
        return float_val
