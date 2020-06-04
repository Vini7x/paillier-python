from paillier import PaillierEncryptor, PaillierEncryptorFloat
from paillier.extra import squared_euclidian, squared_euclidian_oneside
import math


def test_int():
    pe = PaillierEncryptor()
    number1 = 120
    number2 = 120
    number3 = number1 + number2

    enc_1 = pe.encrypt(number1)
    enc_2 = pe.encrypt(number2)
    enc_3 = enc_1 + enc_2

    res1 = pe.decrypt(enc_1)
    res2 = pe.decrypt(enc_2)
    res3 = pe.decrypt(enc_3)

    assert number1 == res1 and number2 == res2 and number3 == res3


def test_float():
    pe = PaillierEncryptorFloat(precision=2)
    number1 = 120.23
    number2 = 125.22
    number2e = -125.22
    number3 = number1 + number2
    number4 = number2e + number1

    enc_1 = pe.encrypt(number1)
    enc_2 = pe.encrypt(number2)
    enc_2e = pe.encrypt(number2e)
    enc_3 = enc_1 + enc_2
    enc_4 = enc_2e + enc_1

    res1 = pe.decrypt(enc_1)
    res2 = pe.decrypt(enc_2)
    res3 = pe.decrypt(enc_3)
    res4 = pe.decrypt(enc_4)

    assert (
        math.isclose(number1, res1, rel_tol=1e-5)
        and math.isclose(number2, res2, rel_tol=1e-5)
        and math.isclose(number3, res3, rel_tol=1e-5)
        and math.isclose(number4, res4, rel_tol=1e-5)
    )


def test_multiplications():
    number1 = 10
    number2 = 2
    number3 = 2.5

    number4 = number1 * number2
    number5 = number1 * number3

    pe1 = PaillierEncryptor()
    pe2 = PaillierEncryptorFloat(precision=2)

    enc11 = pe1.encrypt(number1)
    enc12 = pe2.encrypt(number1)

    res1 = pe1.decrypt(enc11 * number2)
    res2 = pe2.decrypt(enc12 * number3)

    assert number4 == res1 and math.isclose(number5, res2, rel_tol=1e-3)


def test_euclidian():
    pe = PaillierEncryptor()
    p11 = 17
    p12 = 20
    p21 = 30
    p22 = 23

    dist = pe.decrypt(squared_euclidian(pe, [p11, p12], [p21, p22]))

    dist_t = math.pow(p11 - p21, 2) + math.pow(p12 - p22, 2)

    assert dist == dist_t


def test_euclidian_oneside():
    pe = PaillierEncryptor()
    p11 = 17
    p12 = 20
    p21 = 30
    p22 = 23

    p2sqrsum = pe.encrypt((p21 * p21) + (p22 * p22))
    p2e = [pe.encrypt(p21), pe.encrypt(p22)]

    dist = pe.decrypt(squared_euclidian_oneside(pe, [p11, p12], p2sqrsum, p2e))

    dist_t = math.pow(p11 - p21, 2) + math.pow(p12 - p22, 2)

    assert dist == dist_t
