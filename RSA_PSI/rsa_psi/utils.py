import gmpy2
import pybloom_live


eps = 4
m = 2048
e = 0x10001


def inverse(key, x):
    n = key.n
    return gmpy2.invert(x, n)


def encrypt(key, pt):
    e, n = key.e, key.n
    return gmpy2.powmod(pt, e, n)


def decrypt(key, ct):
    d, n = key.d, key.n
    return gmpy2.powmod(ct, d, n)


def sign(key, pt):
    return decrypt(key, pt)


def new_bf():
    mode = pybloom_live.ScalableBloomFilter.SMALL_SET_GROWTH
    return pybloom_live.ScalableBloomFilter(mode=mode)
