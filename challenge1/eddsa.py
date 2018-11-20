# EdDSA signature algorithm
# Taken https://github.com/kudelskisecurity/EdDSA-fault-attack/ and ported to Python 3
# This is based on DJB's python Ed25519 implementation (https://ed25519.cr.yp.to/python/ed25519.py)

import hashlib
import random
from binascii import unhexlify, hexlify
from typing import Tuple

b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def bytes_to_scalar(s):
    assert len(s) == 32, len(s)
    return int(hexlify(s[::-1]), 16)


def bytes_to_clamped_scalar(s: bytes) -> int:
    a_unclamped = bytes_to_scalar(s)
    AND_CLAMP = (1 << 254) - 1 - 7
    OR_CLAMP = (1 << 254)
    a_clamped = (a_unclamped & AND_CLAMP) | OR_CLAMP
    return a_clamped


def H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


# Modular inverse
def inv(a: int, n: int) -> int:
    return pow(a, n-2, n)


d = -121665 * inv(121666, q)
I = pow(2, (q - 1) // 4, q)


def xrecover(y: int) -> int:
    xx = (y * y - 1) * inv(d * y * y + 1, q)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x


By = 4 * inv(5, q)
Bx = xrecover(By)
B = [Bx % q, By % q]


def edwards(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2, q)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2, q)
    return x3 % q, y3 % q


def scalarmult(P, e):
    return fast_multiply(P, e)


def encodeint(y):
    assert 0 <= y < 2 ** 256
    return unhexlify("%064x" % y)[::-1]


def encodepoint(P):
    x = P[0]
    y = P[1]
    assert 0 <= y < (1 << 255)  # always < 0x7fff..ff
    if x & 1:
        y += 1 << 255
    return unhexlify("%064x" % y)[::-1]


def publickey(sk):
    assert len(sk) == 32
    h = H(sk)
    a = bytes_to_clamped_scalar(h[:32])
    A = scalarmult(B, a)
    return encodepoint(A)


def Hint(m):
    h = H(m)
    return int.from_bytes(h, 'little')


def signature(m, sk, pk):
    h = H(sk)
    a = bytes_to_clamped_scalar(h[:32])
    # r = Hint(b''.join([h[i] for i in range(b // 8, b // 4)]) + m)
    r = Hint(h[b // 8:b // 4] + m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def signwitha(m, pk, a):
    if a == 0:
        raise Exception("Error, invalid argument provided")
    r = random.randint(1, 2 ** 256)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodeint(s):
    assert len(s) == 32, len(s)
    return int(hexlify(s[::-1]), 16)


def decodepoint(s: bytes) -> Tuple[int, int]:
    unclamped = int(hexlify(s[:32][::-1]), 16)
    clamp = (1 << 255) - 1
    y = unclamped & clamp  # clear MSB
    x = xrecover(y)
    if bool(x & 1) != bool(unclamped & (1 << 255)):
        x = q - x
    P = x, y
    return P


# Check if the signature s is valid
def checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise Exception("signature length is wrong:", len(s), b // 4, s)
    if len(pk) != b // 8:
        raise Exception("public-key length is wrong")
    R = decodepoint(s[0:b // 8])
    A = decodepoint(pk)
    S = decodeint(s[b // 8:b // 4])
    h = Hint(encodepoint(R) + pk + m)
    if scalarmult(B, S) != edwards(R, scalarmult(A, h)):
        return False
    else:
        return True


# Multiply a point by a scalar using the double-and-add algorithm
def multiply(p: Tuple[int, int, int, int], n: int, adder) -> Tuple[int, int, int, int]:
    if n == 0:
        return 0, 1, 0, 1
    elif n == 1:
        return p
    else:
        x = multiply(adder(p, p), n // 2, adder)
        if n % 2:
            x = adder(x, p)
        return x


# Convert a point to extended format, see
# http://eprint.iacr.org/2008/522.pdf
def to_extended(p: Tuple[int, int]) -> Tuple[int, int, int, int]:
    return p[0], p[1], p[0] * p[1] % q, 1


# Convert back from extended format
def from_extended(p):
    zinv = inv(p[3], q)
    return p[0] * zinv % q, p[1] * zinv % q


def add_extended(p: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int, int, int]:
    _A = p[0] * p2[0] % q
    _B = p[1] * p2[1] % q
    _C = d * p[2] * p2[2] % q
    _D = p[3] * p2[3] % q
    _E = ((p[0] + p[1]) * (p2[0] + p2[1]) - _A - _B) % q
    _F = _D - _C
    _G = _D + _C
    _H = _B + _A  # _B - a * _A, but a = -1
    return _E * _F % q, _G * _H % q, _E * _H % q, _F * _G % q


# fast multiply is an implementation of the multiplication found in
# http://eprint.iacr.org/2008/522.pdf taken from
# https://github.com/vbuterin/ed25519/
def fast_multiply(p, n):
    return from_extended(multiply(to_extended(p), n, adder=add_extended))


# toHex(data) allows to print data as hexadecimal strings
toHex = lambda x: "".join([hex(ord(c))[2:].zfill(2) for c in x])
