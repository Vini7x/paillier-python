from functools import reduce


def squared_euclidian(encryptor, p1, p2):
    p1enc = encryptor.encrypt(sum([p * p for p in p1]))
    p2enc = encryptor.encrypt(sum([p * p for p in p2]))

    p12 = [encryptor.encrypt(q) * (-2 * p) for p, q in zip(p1, p2)]
    p12sum = reduce(lambda x, y: x + y, p12)

    return p1enc + p2enc + p12sum
