from functools import reduce
from paillier.scheme import PaillierEncryptor, PaillierText
from typing import List, TypeVar

Num = TypeVar("Num", int, float)


def squared_euclidian(
    encryptor: PaillierEncryptor, p1: List[Num], p2: List[Num]
) -> PaillierText:
    p1enc = encryptor.encrypt(sum([p * p for p in p1]))
    p2enc = encryptor.encrypt(sum([p * p for p in p2]))

    p12 = [encryptor.encrypt(q) * (-2 * p) for p, q in zip(p1, p2)]
    p12sum = reduce(lambda x, y: x + y, p12)

    return p1enc + p2enc + p12sum


def squared_euclidian_oneside(
    encryptor: PaillierEncryptor,
    p1: List[Num],
    p2sqrsum: PaillierText,
    p2e: List[PaillierText],
) -> PaillierText:
    p1enc = encryptor.encrypt(sum([p * p for p in p1]))
    p2enc = p2sqrsum

    p12 = [q * (-2 * p) for p, q in zip(p1, p2e)]
    p12sum = reduce(lambda x, y: x + y, p12)

    return p1enc + p2enc + p12sum
