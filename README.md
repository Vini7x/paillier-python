# paillier-python

A Python implementation of the Paillier Homomorphic Encryption.

To create a cyphertext just create a ``PaillierEncryptor`` object and call its ``encrypt`` method passing an integer.
Two cyphertexts can be added together by just using the "+" operator on them.

This package depends on libnum, can be installed with ``pip install --user libnum``.

TODO: Implement subtraction.