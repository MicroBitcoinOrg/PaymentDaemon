# Copyright (c) 2016 Ofek Lev
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from hashlib import new, sha256 as _sha256
from collections import namedtuple

FIELD_SIZE = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
GROUP_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
TONELLI_SHANKS_CONSTANT = (FIELD_SIZE + 1) // 4
Point = namedtuple('Point', ('x', 'y'))

def parity(num):
    return num & 1

def x_to_y(x, y_parity):

    y = pow(x ** 3 + 7, TONELLI_SHANKS_CONSTANT, FIELD_SIZE)

    if parity(y) != y_parity:
        y = FIELD_SIZE - y

    return y

def sha256(bytestr):
    return _sha256(bytestr).digest()

def double_sha256(bytestr):
    return _sha256(_sha256(bytestr).digest()).digest()

def double_sha256_checksum(bytestr):
    return double_sha256(bytestr)[:4]

def ripemd160_sha256(bytestr):
    return new('ripemd160', sha256(bytestr)).digest()

hash160 = ripemd160_sha256
