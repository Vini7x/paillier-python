from paillier import PaillierEncryptor, PaillierEncryptorFloat
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
